"""The six PO decisions on the open T-13 items (2026-09-24), each measured against behavior.

Configurable (default = the strict choice, changeable in the panel):
  B2-4  Minimum password length 15 when the password alone can sign in (NIST SP 800-63B)
  B2-6  Sign-in locked after N failed attempts IN A ROW (default 100), back only with success/reset
  B2-8  PIN as first factor stays allowed — explicitly, with its own attempt limit alongside the locks

Fixed:
  F-27  Email collision at OIDC login → clean rejection, no takeover, no 500
  H-3   An IdP address without proof is not used (no account field, no remote email, no name)
  H-5   An admin flag granted by the IdP goes away again when the IdP no longer delivers the group
"""
from __future__ import annotations

import itertools as _itertools
import io
import os
import sqlite3
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from urllib.parse import parse_qs, urlparse
_FALSCH = _itertools.count()   # always NEW wrong passwords: a repetition counts only once since 0.24.9

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.store import Store  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("T-13-Entscheidungen (B2-4, B2-6, B2-8, F-27, H-3, H-5)")
IDP = "https://idp.example.invalid"


def _app(**cfg):
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, base_url="http://testserver", lang="de")
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# ── B2-4: minimum length depending on the factor situation ────────────────────────────────
VIERZEHN, FUENFZEHN, ELF = "Kiefer-Spur-47", "Kiefer-Spur-478", "Kiefer-Spur"
auth, app = _app()
r.check("B2-4: default (no chain, the password signs in alone): 14 characters too short",
        "min. 15" in (auth.password_policy_error(VIERZEHN) or ""), str(auth.password_policy_error(VIERZEHN)))
r.check("… 15 characters pass", auth.password_policy_error(FUENFZEHN) is None,
        str(auth.password_policy_error(FUENFZEHN)))
with TestClient(_app(allow_signup=True)[1]) as c:
    antwort = c.post("/auth/register", data={"username": "neuling", "password": VIERZEHN})
r.check("… and registration adheres to it", antwort.status_code == 400 and "min. 15" in antwort.text,
        f"HTTP {antwort.status_code}")
# A chain with a second factor protects the password only if nobody may set it up themselves:
# with `mfa_enrollment="first_login"` (default) whoever knows only the initial password binds their own
# authenticator at the first login — the password then signs in alone (attack on B2-4).
for kette, einschreiben, erwartet in ((["password", "totp"], "first_login", "min. 15"),
                                      (["password", "totp"], "grace", "min. 15"),
                                      (["password", "totp"], "strict", None),
                                      (["pin", "password"], "strict", None),
                                      (["password"], "strict", "min. 15")):
    a_k, _ = _app(login_chain=kette, pin_enabled="pin" in kette, mfa_enrollment=einschreiben)
    befund = a_k.password_policy_error(ELF)
    r.check(f"B2-4: chain {kette}, enrollment {einschreiben}: 11 characters "
            f"{'pass' if erwartet is None else 'too short'}",
            (befund is None) if erwartet is None else (erwartet in (befund or "")), str(befund))
auth.set_security("password_min_length_single_factor", 8)
r.check("B2-4 configurable: set to 8, the base length applies again",
        auth.password_policy_error(ELF) is None, str(auth.password_policy_error(ELF)))
try:
    auth.set_security("password_min_length_single_factor", 7)
    _unter = False
except ConfigError:
    _unter = True
r.check("… but never below 8 (the limit of the password rule)", _unter)
# (Mutation probe: always return `basis` in `_passwort_mindestlaenge` → the first three red;
#  `_passwort_allein_moeglich` always True → the two chains with a second factor red.)

# ── B2-6: failed attempts in a row, without time window ──────────────────────────────────
auth, app = _app()
for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
             ("account_max_consecutive_failures", 10)):
    auth.set_security(k, v)
PW = "Serien-Passwort-2026"
uid = auth.create_user("serie", password=PW, email="serie@example.com")
c = TestClient(app)


def _login(client, name, pw):
    return client.post("/auth/login", data={"username": name, "password": pw}, follow_redirects=False)


for _ in range(10):
    _login(c, "serie", f"falsch-falsch-falsch-{next(_FALSCH)}")
gesperrt = _login(c, "serie", PW)
r.check("B2-6: after 10 failed attempts in a row the sign-in locks — even with the correct password",
        gesperrt.status_code == 429 and "in Folge" in gesperrt.text, f"HTTP {gesperrt.status_code}")
r.check("… the lock appears exactly once in the audit log",
        sum(1 for z in auth.store.recent_audit(200) if z["event"] == "lockout_series") == 1)
for _ in range(10):
    _login(c, "gibt-es-nicht", f"falsch-falsch-falsch-{next(_FALSCH)}")
fremd = _login(c, "gibt-es-nicht", f"falsch-falsch-falsch-{next(_FALSCH)}")
r.check("… an unknown name gets the same response (no oracle for existing accounts)",
        fremd.status_code == 429 and "in Folge" in fremd.text, f"HTTP {fremd.status_code}")

# Aged, otherwise this would test only the 90 days and not the limit (as measured: the mutation
# "gc also clears triggered ones" stayed green as long as the series was fresh).
auth.store._exec("UPDATE fehlserie SET zuletzt = zuletzt - 91 * 86400 WHERE topf='serie'")
auth.gc()
r.check("B2-6: gc() does not clear a triggered series, not even after 90 days (it does not expire)",
        auth.store.fehlserie("serie") == 10, str(auth.store.fehlserie("serie")))
auth.store.fehlserie_erhoehen("alt-und-halb")
auth.store._exec("UPDATE fehlserie SET zuletzt = zuletzt - 91 * 86400 WHERE topf='alt-und-halb'")
auth.gc()
r.check("… but it does clear one that was not triggered after 90 days of quiet", auth.store.fehlserie("alt-und-halb") == 0)

auth.lift_lockout(uid, methods=("password",))           # the path of the self-service reset
r.check("B2-6: a reset ends the series (rebind)", _login(c, "serie", PW).status_code == 303,
        "still locked after the reset")

uid2 = auth.create_user("wechsel", password=PW)
for _ in range(9):
    _login(TestClient(app), "wechsel", f"falsch-falsch-falsch-{next(_FALSCH)}")
_login(TestClient(app), "wechsel", PW)                        # successful access
for _ in range(9):
    _login(TestClient(app), "wechsel", f"falsch-falsch-falsch-{next(_FALSCH)}")
r.check("B2-6: a successful access resets the series (9 + success + 9 does not lock)",
        _login(TestClient(app), "wechsel", PW).status_code == 303, str(auth.store.fehlserie("wechsel")))

auth._record_login("wechsel", "198.51.100.1", False, "password_change")
r.check("B2-6: a miss that is not a sign-in (password change) does not count",
        auth.store.fehlserie("wechsel") == 0, str(auth.store.fehlserie("wechsel")))

for _ in range(10):
    _login(TestClient(app), "wechsel", f"falsch-falsch-falsch-{next(_FALSCH)}")
admin_id = auth.create_user("chefin", password=PW, is_admin=True)
ca = TestClient(app)
_login(ca, "chefin", PW)
neu = ca.post(f"/auth/admin/api/users/{uid2}/password", json={"password": "Ganz-Neues-Passwort-1"})
r.check("B2-6: the password reset in the panel ends the series",
        neu.status_code == 200 and _login(TestClient(app), "wechsel", "Ganz-Neues-Passwort-1").status_code == 303,
        f"HTTP {neu.status_code}, Serie {auth.store.fehlserie('wechsel')}")

for _ in range(10):
    _login(TestClient(app), "wechsel", f"falsch-falsch-falsch-{next(_FALSCH)}")
from tinysesam.__main__ import main as _cli  # noqa: E402
# The CLI ends via `sys.exit` — uncaught that ended this test with exit 0, in the middle of the run
# and green (a skip is not a green).
_code = 0
with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
    try:
        _cli(["unlock", "--db", auth.cfg.db_path, "wechsel"])
    except SystemExit as e:
        _code = e.code or 0
r.check("B2-6: `tinysesam unlock` ends the series", _code == 0 and auth.store.fehlserie("wechsel") == 0,
        f"exit {_code}, Serie {auth.store.fehlserie('wechsel')}")

for wert, gilt in ((9, False), (10, True), (100000, True), (100001, False)):
    try:
        auth.set_security("account_max_consecutive_failures", wert)
        ok_ = True
    except ConfigError:
        ok_ = False
    r.check(f"B2-6 configurable: {wert} {'erlaubt' if gilt else 'abgewiesen'}", ok_ is gilt)
# (Mutation probes: delete the series check in `begin_attempt` → first check red;
#  delete `fehlserie_loeschen` in `lift_lockout` → reset/panel red; delete the condition
#  `anzahl < ?` in `gc_fehlserien` → "does not expire" red.)

# Findings from the attack on B2-6 — each one its own test.
auth, app = _app()
for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
             ("account_max_consecutive_failures", 10)):
    auth.set_security(k, v)
uid_a = auth.create_user("atom", password=PW)
for _ in range(9):
    auth._record_login("atom", "198.51.100.2", False, "password",
                       versuch=auth._begin_attempt("atom", "198.51.100.2", "password"))
offen = [auth._begin_attempt("atom", f"198.51.100.{10 + i}", "password") for i in range(5)]
r.check("B2-6 atomic: at the limit exactly ONE running attempt gets through, not every one",
        sum(1 for v in offen if v is not None) == 1, str(offen))
auth._record_login("atom", "198.51.100.10", True, "password", versuch=next(v for v in offen if v))
r.check("… and a correct attempt takes back its pre-booking, but does not clear the series",
        auth.store.fehlserie("atom") == 9, str(auth.store.fehlserie("atom")))
v = auth._begin_attempt("atom", "198.51.100.3", "password")
auth._versuch_zuruecknehmen(v)
r.check("B2-6: a withdrawn attempt (directory outage) does not count",
        auth.store.fehlserie("atom") == 9, str(auth.store.fehlserie("atom")))

uid_t = auth.create_user("zweit", password=PW)
for _ in range(10):
    auth._record_login("zweit", "198.51.100.4", False, "totp",
                       versuch=auth._begin_attempt("zweit", "198.51.100.4", "totp"))
auth.lift_lockout(uid_t, methods=("password",))            # self-service reset
r.check("B2-6 + R4-13: the self-service reset does NOT clear TOTP misses of the series",
        auth.store.fehlserie("zweit") == 10 and auth._begin_attempt("zweit", "198.51.100.5", "password") is None,
        str(auth.store.fehlserie("zweit")))
# Conversely the FIRST factors: anyone can send wrong PINs, even without knowing a secret.
# If they stayed after the reset, the reset the message recommends would no longer help (R2-2).
uid_pin = auth.create_user("pinopfer", password=PW)
for _ in range(10):
    auth._record_login("pinopfer", "198.51.100.8", False, "pin",
                       versuch=auth._begin_attempt("pinopfer", "198.51.100.8", "pin"))
auth.lift_lockout(uid_pin, methods=("password",))          # self-service reset
r.check("B2-6: the reset clears a series of wrong PINs (first factor, producible by anyone)",
        auth.store.fehlserie("pinopfer") == 0, str(auth.store.fehlserie("pinopfer")))

chefin_t = auth.create_user("chefin-t", password=PW, is_admin=True)
cpt = TestClient(app)
cpt.post("/auth/login", data={"username": "chefin-t", "password": PW}, follow_redirects=False)
neu_t = cpt.post(f"/auth/admin/api/users/{uid_t}/password", json={"password": "Vom-Betreiber-Gesetzt-1"})
r.check("… the operator clears it entirely (password reset in the panel, also the TOTP part)",
        neu_t.status_code == 200 and auth.store.fehlserie("zweit") == 0, str(auth.store.fehlserie("zweit")))
# And via the path the routes take: a non-login attempt pre-books nothing.
v_pc = auth._begin_attempt("zweit", "198.51.100.6", "password_change")
auth._record_login("zweit", "198.51.100.6", False, "password_change", versuch=v_pc)
r.check("B2-6: a miss at the password change (via begin_attempt) books no series",
        auth.store.fehlserie("zweit") == 0, str(auth.store.fehlserie("zweit")))

# ── B2-6 × directory: the series under the name in the directory (G5, G5-N1) ───────────────────
# The series counts under the TYPED identifier. After a rename in the directory (locally
# `alice`, bound via entryUUID, there `alice.neu`) the person types `alice.neu`. Until 2026-09-26
# no way back cleared the series under it: own typos added up over the years, a
# stranger could lock them out permanently with enough failed attempts, and `tinysesam unlock alice.neu` aborted
# with "No account".
class _Verzeichnis:
    """Dummy of the LDAP client after the bind: the entry for the typed identifier (with a
    filter over `uid` AND `mail` also for the address)."""

    def __init__(self, eintraege):
        self.eintraege = eintraege

    def authenticate(self, username, password):
        e = self.eintraege.get(username)
        if not e or e["pw"] != password:
            return None
        return {"username": username, "email": e.get("email"), "name": username, "groups": [],
                "id": e.get("id"), "email_verified": None}


LPW = "Verzeichnis-Pw1"
auth_v, app_v = _app(ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
                     ldap_auto_create=True, passkey_enabled=False)
for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
             ("account_max_consecutive_failures", 10)):
    auth_v.set_security(k, v)
auth_v.ldap = _Verzeichnis({"alice": {"pw": LPW, "id": "uuid-alice"}})
_erst_v = _login(TestClient(app_v), "alice", LPW)
uid_v = auth_v.store.get_user_by_name("alice")["id"]


def _bindungsname(uid):
    z = auth_v.store._one("SELECT name_topf FROM federated_identity WHERE user_id=?", (uid,))
    return z["name_topf"] if z else "(keine Bindung)"


_erst_name = _bindungsname(uid_v)
auth_v.ldap = _Verzeichnis({"alice.neu": {"pw": LPW, "id": "uuid-alice"}})     # renamed in the directory
for _ in range(3):
    _login(TestClient(app_v), "alice.neu", f"falsch-falsch-1-{next(_FALSCH)}")
_drei_v = auth_v.store.fehlserie("alice.neu")
_voll_v = _login(TestClient(app_v), "alice.neu", LPW)
# (Mutation probe: omit the name from the binding in `Store.zaehl_kennungen` → 3 → red.)
r.check("G5: after the rename in the directory the full sign-in ends the series under the "
        "new name (and clears its window)",
        _erst_v.status_code == 303 and _drei_v == 3 and _voll_v.status_code == 303
        and auth_v.store.fehlserie("alice.neu") == 0 and auth_v.store.count_fails(0, username="alice.neu") == 0,
        f"HTTP {_erst_v.status_code}/{_voll_v.status_code}, Serie {_drei_v} → {auth_v.store.fehlserie('alice.neu')}")
r.check("… the same account; the directory name is on the binding — only because it is not the account's own",
        auth_v.store.get_user(uid_v)["username"] == "alice" and _erst_name is None
        and _bindungsname(uid_v) == "alice.neu", f"{_erst_name!r} → {_bindungsname(uid_v)!r}")

for _ in range(10):
    _login(TestClient(app_v), "alice.neu", f"falsch-falsch-1-{next(_FALSCH)}")
_gesperrt_v = _login(TestClient(app_v), "alice.neu", LPW)
auth_v._serie_beenden(uid_v)
# (Mutation probe: only name and address again in `_serie_beenden` → red.)
r.check("G5: at the limit (429 even with the correct password) the operator path "
        "(`_serie_beenden`) clears the series under the directory name",
        _gesperrt_v.status_code == 429 and auth_v.store.fehlserie("alice.neu") == 0
        and _login(TestClient(app_v), "alice.neu", LPW).status_code == 303,
        f"HTTP {_gesperrt_v.status_code}, Serie {auth_v.store.fehlserie('alice.neu')}")
for _ in range(10):
    _login(TestClient(app_v), "alice.neu", f"falsch-falsch-1-{next(_FALSCH)}")
auth_v.create_user("chefin-v", password=PW, is_admin=True)
_cv = TestClient(app_v)
_login(_cv, "chefin-v", PW)
_panel_v = _cv.post(f"/auth/admin/api/users/{uid_v}/password", json={"password": "Betreiber-Pw-15"})
r.check("… likewise the password reset in the panel", _panel_v.status_code == 200
        and auth_v.store.fehlserie("alice.neu") == 0, f"HTTP {_panel_v.status_code}, {auth_v.store.fehlserie('alice.neu')}")


def _unlock(kennung):
    aus, fehl, code = io.StringIO(), io.StringIO(), 0
    with redirect_stdout(aus), redirect_stderr(fehl):
        try:
            _cli(["unlock", "--db", auth_v.cfg.db_path, kennung])
        except SystemExit as e:
            code = e.code or 0
    return code, aus.getvalue() + fehl.getvalue()


for _ in range(10):
    _login(TestClient(app_v), "alice.neu", f"falsch-falsch-1-{next(_FALSCH)}")
_login(TestClient(app_v), "alice", f"falsch-falsch-1-{next(_FALSCH)}")          # the old name: gone from the directory
_code_v, _text_v = _unlock("alice.neu")
# (Mutation probe: delete `konto_mit_bindungsname` → the account is not found, the series
#  under `alice` stays → red.)
r.check("G5: `tinysesam unlock alice.neu` — the name as typed — finds the account and ends "
        "its series under all identifiers",
        _code_v == 0 and "Lockout for 'alice.neu' lifted" in _text_v
        and auth_v.store.fehlserie("alice.neu") == 0 and auth_v.store.fehlserie("alice") == 0,
        f"exit {_code_v}, {_text_v!r}, Serie {auth_v.store.fehlserie('alice.neu')}/{auth_v.store.fehlserie('alice')}")
# Existing data: the series is already full, but the directory name was never noted (it only arises with the
# next SUCCESSFUL sign-in — and that is locked).
auth_v.store._exec("UPDATE federated_identity SET name_topf = NULL")
for _ in range(10):
    _login(TestClient(app_v), "alice.neu", f"falsch-falsch-1-{next(_FALSCH)}")
_code_b, _text_b = _unlock("alice.neu")
# (Mutation probe: rebuild the abort "No account" before the clearing → red.)
r.check("… also in existing data without a note: no account, but the counters under the identifier are cleared (rc 0)",
        _code_b == 0 and "No account" in _text_b and auth_v.store.fehlserie("alice.neu") == 0
        and _login(TestClient(app_v), "alice.neu", LPW).status_code == 303,
        f"exit {_code_b}, {_text_b!r}, Serie {auth_v.store.fehlserie('alice.neu')}")
_code_n, _text_n = _unlock("gibt-es-nirgends")
r.check("… an identifier without account and without counters stays an error (rc 1)",
        _code_n == 1 and "No account" in _text_n, f"exit {_code_n}, {_text_n!r}")

# The guard: a directory filter over `mail` also resolves an identifier to a third party whose
# `mail` attribute is the address of a LOCAL account (default `ldap_email_trusted=False`). Until
# 2026-09-26 every sign-in of the third party cleared the owner's counters — window (G5-N1) and series
# (G5): unlimited guessing against her account. G5-N1 allowed the third party's sign-in and protected
# only the counters; the opposite direction stayed open (the owner cleared the counters under which
# guessing against HIS LDAP password took place). Since the review round 2026-09-27 (p1-d, PO decision C) an
# identifier never checks the secrets of two accounts: the third party's sign-in is rejected and booked as a
# failed attempt before `check_ldap` writes anything.
import logging as _log_g5  # noqa: E402
from tinysesam import security as _sec_g5  # noqa: E402

_chefin_w = auth_v.create_user("chefin", password=PW, email="chefin@example.com")
auth_v.ldap = _Verzeichnis({"chefin@example.com": {"pw": LPW, "id": "uuid-dritter", "email": "chefin@example.com"}})
for _ in range(4):
    _login(TestClient(app_v), "chefin@example.com", f"falsch-falsch-1-{next(_FALSCH)}")
_vorher_w = (auth_v.store.count_fails(0, username="chefin@example.com"), auth_v.store.fehlserie("chefin@example.com"))
_konten_w = auth_v.store.user_count()
_puffer_w = io.StringIO()
_haken_w = _log_g5.StreamHandler(_puffer_w)
_sec_g5.seclog.addHandler(_haken_w)
try:
    _dritter = _login(TestClient(app_v), "chefin@example.com", LPW)
finally:
    _sec_g5.seclog.removeHandler(_haken_w)
_abgewiesen_w = [dict(z) for z in auth_v.store._all("SELECT * FROM audit WHERE event='ldap_identifier_rejected'")]
# (Mutation probe: switch off the check against `nur_konto` in `_fremde_identitaet_aufloesen` → the
#  third party gets 303 and an account → red.)
r.check("p1-d (C): the sign-in of a directory third party under the address of a local account is "
        "rejected and booked as a failed attempt — without account, without binding",
        _vorher_w == (4, 4) and _dritter.status_code == 401
        and auth_v.store.get_federated_user("ldap", "uuid-dritter") is None
        and auth_v.store.user_count() == _konten_w
        and auth_v.store.count_fails(0, username="chefin@example.com") == 5
        and auth_v.store.fehlserie("chefin@example.com") == 5,
        f"vorher {_vorher_w}, HTTP {_dritter.status_code}, "
        f"{auth_v.store.count_fails(0, username='chefin@example.com')}/{auth_v.store.fehlserie('chefin@example.com')}")
r.check("… with reason in the audit log (identifier_of_two_accounts, both accounts) and remedy in the security log",
        len(_abgewiesen_w) == 1
        and _abgewiesen_w[0]["detail"] == f"reason=identifier_of_two_accounts local={_chefin_w} directory=new"
        and "tinysesam rename" in _puffer_w.getvalue(), f"{_abgewiesen_w} {_puffer_w.getvalue()[:200]!r}")
_inhaberin = _login(TestClient(app_v), "chefin@example.com", PW)
# Until 2026-09-27 this counter-check held on to the defect: the 4 failed attempts also applied to the
# third party's LDAP password, and the owner cleared them. Now only her own secret opens a session under her
# address — her sign-in clears what can only be directed against her.
r.check("… the owner clears both with her sign-in — under her address only her secret still applies",
        _inhaberin.status_code == 303 and auth_v.store.count_fails(0, username="chefin@example.com") == 0
        and auth_v.store.fehlserie("chefin@example.com") == 0,
        f"HTTP {_inhaberin.status_code}, {auth_v.store.count_fails(0, username='chefin@example.com')}")


# ── Review round locks/counters (2026-09-27): one identifier, one account ──────────────────────
def _ldap_app():
    a, ap = _app(ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
                 ldap_auto_create=True, passkey_enabled=False)
    for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
                 ("account_max_consecutive_failures", 10)):
        a.set_security(k, v)
    return a, ap


def _sitzung_von(a, antwort):
    tok = antwort.cookies.get(a.session_cookie_name)
    z = a.store._one("SELECT user_id FROM session WHERE token_hash=?", (a.store.session_hash(tok),)) if tok else None
    return z["user_id"] if z else None


MPW = "Mallory-Pw-15xy"
# p1-d (C), existing data: Mallory is already called `alice.neu` locally BEFORE Alice is renamed so in the directory.
# Under `alice.neu` the route then checked Mallory's password AND Alice's LDAP password; with every
# sign-in of her own Mallory cleared window and series — 120 failed attempts from one IP, no lock,
# after which Alice's correct password opened HER session. Now it opens nothing under `alice.neu`.
a_d, ap_d = _ldap_app()
a_d.ldap = _Verzeichnis({"alice": {"pw": LPW, "id": "uuid-alice"}})
_login(TestClient(ap_d), "alice", LPW)
_alice_d = a_d.store.get_user_by_name("alice")["id"]
_mallory_d = a_d.create_user("alice.neu", password=MPW)
a_d.ldap = _Verzeichnis({"alice.neu": {"pw": LPW, "id": "uuid-alice"}})
for _ in range(10):
    for _ in range(4):
        _login(TestClient(ap_d, client=("203.0.113.66", 1)), "alice.neu", f"falsch-falsch-1-{next(_FALSCH)}")
    _login(TestClient(ap_d, client=("203.0.113.66", 1)), "alice.neu", MPW)
_ev_d0 = [e["event"] for e in a_d.own_events(_mallory_d, 1000)]
_login(TestClient(ap_d, client=("203.0.113.66", 1)), "alice.neu", f"falsch-falsch-1-{next(_FALSCH)}")
_ev_d1 = [e["event"] for e in a_d.own_events(_mallory_d, 1000)]
_treffer_d = _login(TestClient(ap_d, client=("203.0.113.66", 1)), "alice.neu", LPW)
_ev_d2 = [e["event"] for e in a_d.own_events(_mallory_d, 1000)]
# (Mutation probe: switch off the check against `nur_konto` → 303, session of Alice → red.)
r.check("p1-d (C): a local account under the directory name of another person — their correct "
        "LDAP password opens no session under this identifier, guessing there is worthless",
        _treffer_d.status_code == 401 and _sitzung_von(a_d, _treffer_d) is None
        and a_d.store.get_federated_user("ldap", "uuid-alice") == _alice_d
        and a_d.store._one("SELECT name_topf FROM federated_identity WHERE user_id=?", (_alice_d,))["name_topf"] is None,
        f"HTTP {_treffer_d.status_code}, Sitzung {_sitzung_von(a_d, _treffer_d)}")
# The rejection arises only if the LDAP password was right — on Mallory's account page it would be the
# oracle. (Mutation probe: take `ldap_identifier_rejected` out of `_EIGENE_ANSICHT` → red.)
r.check("… and Mallory's account page sees a hit like a miss (no oracle about the rejection)",
        len(_ev_d1) - len(_ev_d0) == len(_ev_d2) - len(_ev_d1) == 1 and _ev_d1[0] == _ev_d2[0]
        and bool(a_d.store._one("SELECT 1 AS x FROM audit WHERE event='ldap_identifier_rejected'")),
        f"{_ev_d0[:2]} {_ev_d1[:2]} {_ev_d2[:2]}")
# Read path with OLD rows (an older version after a rollback wrote them): the rejection under its up-to-0.24.x
# name stays just as hidden, and the old name `login_lokal` is shown in the English spelling.
a_d.store.audit_log("ldap_kennung_abgewiesen", "alice.neu", "203.0.113.66", "grund=kennung_zweier_konten")
a_d.store.audit_log("login_lokal", "alice.neu", "203.0.113.66", "password")
_ev_d3 = [e["event"] for e in a_d.own_events(_mallory_d, 1000)]
r.check("… old rows: `ldap_kennung_abgewiesen` stays hidden on the account page, `login_lokal` appears as `login_local`",
        len(_ev_d3) - len(_ev_d2) == 1 and _ev_d3[0] == "login_local"
        and "ldap_kennung_abgewiesen" not in _ev_d3 and "ldap_identifier_rejected" not in _ev_d3,
        f"{_ev_d2[:2]} {_ev_d3[:3]}")
r.check("… Mallory's own sign-in continues to work (counter-check)",
        _login(TestClient(ap_d), "alice.neu", MPW).status_code == 303)
a_d.change_username(_mallory_d, "mallory", by_operator=True)
_danach_d = _login(TestClient(ap_d), "alice.neu", LPW)
r.check("… after the rename by the operator (the remedy from the log line) Alice signs in under "
        "`alice.neu`", _danach_d.status_code == 303 and _sitzung_von(a_d, _danach_d) == _alice_d,
        f"HTTP {_danach_d.status_code}")

# p1-d (A): Once Alice has signed in under `alice.neu`, the name is on her binding — and no
# other account can take it: self-service, registration, admin, CLI, the database itself.
a_a, ap_a = _ldap_app()
a_a.ldap = _Verzeichnis({"alice": {"pw": LPW, "id": "uuid-alice"}})
_login(TestClient(ap_a), "alice", LPW)
_alice_a = a_a.store.get_user_by_name("alice")["id"]
a_a.ldap = _Verzeichnis({"alice.neu": {"pw": LPW, "id": "uuid-alice"}})
_login(TestClient(ap_a), "alice.neu", LPW)
_mallory_a = a_a.create_user("mallory", password=MPW)
_vergeben_a = a_a.identifier_taken("ALICE.NEU")
try:
    a_a.change_username(_mallory_a, "alice.neu", by_operator=True)    # not even the operator
    _selbst_a = "umbenannt"
except ValueError:
    _selbst_a = "abgewiesen"
try:
    a_a.store.set_username(_mallory_a, "Alice.Neu")
    _roh_a = "geschrieben"
except sqlite3.IntegrityError:
    _roh_a = "IntegrityError"
try:
    a_a.store.create_user("alice.neu")
    _anlage_a = "angelegt"
except sqlite3.IntegrityError:
    _anlage_a = "IntegrityError"
# Registration no longer exists alongside LDAP (PO decision 2026-09-27) — the setup fails.
try:
    _app(ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
         passkey_enabled=False, allow_signup=True)
    _reg_a = "gebaut"
except ConfigError as _e_reg:
    _reg_a = str(_e_reg)
_cli_aus_a = io.StringIO()
with redirect_stdout(_cli_aus_a), redirect_stderr(_cli_aus_a):
    try:
        _cli(["rename", "--db", a_a.cfg.db_path, "mallory", "alice.neu"])
        _cli_a = 0
    except SystemExit as e:
        _cli_a = e.code
# (Mutation probes: take `konto_mit_verzeichnisname` out of `identifier_taken` → the pre-check red;
#  take the federated part out of the identifier triggers → "Datenbank" red.)
r.check("p1-d (A): the directory name of another account counts as taken (pre-check, any spelling)",
        _vergeben_a is not None and _vergeben_a["id"] == _alice_a, str(_vergeben_a))
r.check("… and the database rejects it — rename and create (identifier trigger)",
        _roh_a == "IntegrityError" and _anlage_a == "IntegrityError", f"{_roh_a} {_anlage_a}")
r.check("… renaming (also by the operator) and `tinysesam rename` refuse, registering does not "
        "exist alongside LDAP at all",
        _selbst_a == "abgewiesen" and "allow_signup" in _reg_a and "ldap_enabled" in _reg_a and _cli_a == 1
        and "name in the directory" in _cli_aus_a.getvalue()
        and a_a.store.get_user(_mallory_a)["username"] == "mallory",
        f"{_selbst_a}, registration {_reg_a}, CLI rc {_cli_a} {_cli_aus_a.getvalue()[:120]!r}")
# Alongside LDAP nobody renames themselves, not even to a free name (PO decision
# 2026-09-27): otherwise a local account could take the directory name of a person who has
# never signed in, and lock them out. (Mutation probe: switch off the check in `change_username`
# → red; the flag of the account page → red.)
try:
    a_a.change_username(_mallory_a, "mallory2")
    _ldap_selbst = "umbenannt"
except ValueError as _e_sb:
    _ldap_selbst = str(_e_sb)
_c_sb = TestClient(ap_a)
_login(_c_sb, "mallory", MPW)
_seite_sb = _c_sb.get("/auth/account", headers={"accept": "text/html"}).text
_route_sb = _c_sb.post("/auth/account/username", json={"username": "mallory3"})
r.check("Alongside LDAP: no self-rename (method, route, account page)",
        _ldap_selbst == a_a.t("api.username_from_directory") and _route_sb.status_code in (400, 403)
        and "data-act=setname" not in _seite_sb and a_a.store.get_user(_mallory_a)["username"] == "mallory",
        f"{_ldap_selbst!r} HTTP {_route_sb.status_code}")
a_a.change_username(_alice_a, "alice.neu", by_operator=True)
r.check("… Alice's account may take it (her own binding does not count)",
        a_a.store.get_user(_alice_a)["username"] == "alice.neu")

# p1-b: The operator renames an LDAP account whose name is the directory name (G13). Until then
# the binding held NULL (the name was its own, after all), and after the rename `alice` dropped out of
# `zaehl_kennungen` and out of the identifier space: if a stranger filled the series under it, neither the
# panel reset nor a full sign-in by another route helped (429 until `tinysesam unlock alice`), and another
# account could call itself `alice`.
a_b, ap_b = _ldap_app()
a_b.ldap = _Verzeichnis({"alice": {"pw": LPW, "id": "uuid-alice"}})
_login(TestClient(ap_b), "alice", LPW)
_alice_b = a_b.store.get_user_by_name("alice")["id"]
a_b.create_user("chefin-b", password=PW, is_admin=True)
a_b.change_username(_alice_b, "alice.meier", by_operator=True)
_kennungen_b = a_b.store.zaehl_kennungen(_alice_b)
for _i in range(10):
    _login(TestClient(ap_b, client=(f"203.0.113.{_i + 10}", 1)), "alice", f"falsch-falsch-1-{next(_FALSCH)}")
_vor_b = _login(TestClient(ap_b), "alice", LPW).status_code
_c_b = TestClient(ap_b)
_login(_c_b, "chefin-b", PW)
_panel_b = _c_b.post(f"/auth/admin/api/users/{_alice_b}/password", json={"password": "Betreiber-Pw-15"}).status_code
_nach_b = _login(TestClient(ap_b), "alice", LPW)
_mallory_b = a_b.create_user("mallory", password=MPW)
# (Mutation probe: omit `_verzeichnisname_merken` in `_kennung_setzen` → series stays, 429, and
#  `mallory` may call itself `alice` → red.)
r.check("p1-b: after the rename by the operator the old name counts as directory name — the "
        "panel reset clears the series under it, the LDAP sign-in works again",
        _kennungen_b == {"alice", "alice.meier"} and _vor_b == 429 and _panel_b == 200
        and _nach_b.status_code == 303 and _sitzung_von(a_b, _nach_b) == _alice_b,
        f"{_kennungen_b}, {_vor_b}/{_panel_b}/{_nach_b.status_code}")
r.check("… and no other account can call itself that",
        a_b.identifier_taken("alice", exclude_id=_mallory_b) is not None)

# p1-a: After a rename and reassignment in the directory the previous owner kept the name on
# its binding. Every full sign-in of the previous owner (and every operator reset for it) ended
# the series under which guessing against the NEW owner took place, and `tinysesam unlock x` named the
# account with the younger binding and cleared its own series too.
a_x, ap_x = _ldap_app()
a_x.ldap = _Verzeichnis({"x": {"pw": LPW, "id": "uuid-a"}, "berta": {"pw": LPW, "id": "uuid-b"}})
_login(TestClient(ap_x), "berta", LPW)
_berta_x = a_x.store.get_user_by_name("berta")["id"]
a_x.store._exec("UPDATE federated_identity SET gebunden_at = gebunden_at - 100 WHERE user_id=?", (_berta_x,))
_login(TestClient(ap_x), "x", LPW)
_anton_x = a_x.store.get_user_by_name("x")["id"]
a_x.change_username(_anton_x, "anton", by_operator=True)
a_x.set_password(_anton_x, PW)
a_x.ldap = _Verzeichnis({"x.alt": {"pw": LPW, "id": "uuid-a"}, "x": {"pw": LPW, "id": "uuid-b"}})
_login(TestClient(ap_x), "x", LPW)                  # Berta is now called `x` in the directory


def _bindungsname_x(uid):
    return a_x.store._one("SELECT name_topf FROM federated_identity WHERE user_id=?", (uid,))["name_topf"]


_namen_x = (_bindungsname_x(_anton_x), _bindungsname_x(_berta_x))
for _i in range(9):
    _login(TestClient(ap_x, client=(f"203.0.113.{_i + 10}", 1)), "x", f"falsch-falsch-1-{next(_FALSCH)}")
_login(TestClient(ap_x), "anton", PW)                # full sign-in of the previous owner
a_x._serie_beenden(_anton_x)                         # operator reset for him
# (Mutation probe: omit the deletion on foreign bindings in `bindung_name_setzen` → Anton's
#  binding keeps `x` → red.)
r.check("p1-a: the most recent sign-in under `x` proves who owns the name — the previous owner loses it, "
        "his sign-in and his reset leave the series of the new owner standing",
        _namen_x == (None, "x") and a_x.store.zaehl_kennungen(_anton_x) == {"anton"}
        and a_x.store.fehlserie("x") == 9, f"{_namen_x}, {a_x.store.zaehl_kennungen(_anton_x)}, {a_x.store.fehlserie('x')}")
_login(TestClient(ap_x, client=("203.0.113.99", 1)), "x", f"falsch-falsch-1-{next(_FALSCH)}")
for _i in range(3):
    _login(TestClient(ap_x, client=(f"203.0.113.{_i + 50}", 1)), "anton", f"falsch-falsch-1-{next(_FALSCH)}")
_aus_x = io.StringIO()
with redirect_stdout(_aus_x), redirect_stderr(_aus_x):
    try:
        _cli(["unlock", "--db", a_x.cfg.db_path, "x"])
    except SystemExit:
        pass    # the CLI ends with sys.exit; what is measured is the output and the database
_unlock_x = [dict(z) for z in a_x.store._all("SELECT username, detail FROM audit WHERE event='unlock_cli'")]
r.check("… `tinysesam unlock x` names the new owner and leaves the previous owner's own series standing",
        [z["username"] for z in _unlock_x] == ["berta"] and a_x.store.fehlserie("x") == 0
        and a_x.store.fehlserie("anton") == 3, f"{_unlock_x}, anton {a_x.store.fehlserie('anton')}")
# Existing data: both still carry the name (written before this version). Then it counts for neither, and
# `unlock` names no account (which one signed in most recently like this is recorded nowhere).
a_x.store._exec("UPDATE federated_identity SET name_topf='x' WHERE user_id=?", (_anton_x,))
for _i in range(3):
    _login(TestClient(ap_x, client=(f"203.0.113.{_i + 70}", 1)), "x", f"falsch-falsch-1-{next(_FALSCH)}")
_login(TestClient(ap_x), "anton", PW)
_serie_x2 = a_x.store.fehlserie("x")
_aus_x2 = io.StringIO()
with redirect_stdout(_aus_x2), redirect_stderr(_aus_x2):
    try:
        _cli(["unlock", "--db", a_x.cfg.db_path, "x"])
    except SystemExit:
        pass    # the CLI ends with sys.exit; what is measured is the output and the database
# (Mutation probes: omit the second safeguard in `zaehl_kennungen` → Anton's sign-in clears the
#  series → red; `konto_mit_bindungsname` by `gebunden_at` again → names anton → red.)
r.check("… in existing data with two carriers: the name counts for neither, `unlock` names none and clears only under `x`",
        _serie_x2 == 3 and a_x.store.fehlserie("x") == 0
        and "x" not in a_x.store.zaehl_kennungen(_anton_x) and "x" not in a_x.store.zaehl_kennungen(_berta_x)
        and "No account 'x'" in _aus_x2.getvalue(), f"Serie {_serie_x2}, {_aus_x2.getvalue()!r}")

# A stale note does not stop a new person: if someone ELSE is now called `y` in the directory
# (reassignment), their first sign-in creates the account `y` — the note on the previous owner is
# stale and is deleted. (Mutation probe: omit `verzeichnisname_freigeben` in `check_ldap` →
# the creation fails as "taken", 401 → red.)
a_y, ap_y = _ldap_app()
a_y.ldap = _Verzeichnis({"y": {"pw": LPW, "id": "uuid-a"}})
_login(TestClient(ap_y), "y", LPW)
_alt_y = a_y.store.get_user_by_name("y")["id"]
a_y.change_username(_alt_y, "yves", by_operator=True)           # notes `y` (p1-b)
_vermerk_y = a_y.store._one("SELECT name_topf FROM federated_identity WHERE user_id=?", (_alt_y,))["name_topf"]
a_y.ldap = _Verzeichnis({"y.alt": {"pw": LPW, "id": "uuid-a"}, "y": {"pw": LPW, "id": "uuid-c"}})
_neu_y = _login(TestClient(ap_y), "y", LPW)
_konto_y = a_y.store.get_user_by_name("y")
r.check("p1-a: a new directory entry under a noted name creates its account; the note "
        "on the previous owner is dropped",
        _vermerk_y == "y" and _neu_y.status_code == 303 and _konto_y is not None
        and _sitzung_von(a_y, _neu_y) == _konto_y["id"] != _alt_y
        and a_y.store._one("SELECT name_topf FROM federated_identity WHERE user_id=?", (_alt_y,))["name_topf"] is None,
        f"Vermerk {_vermerk_y!r}, HTTP {_neu_y.status_code}")

# p1-d (C), address: filter over uid AND mail, `ldap_email_trusted=False` (default) — LDAP accounts
# carry no address locally. A local account carries Alice's directory address (in the finding via
# registration, which has not existed alongside LDAP since 2026-09-27; here created by the operator or
# from existing data); until 2026-09-27 its own sign-in under the address cleared the counters against
# Alice's LDAP password, without any rename.
a_m, ap_m = _ldap_app()
_alice_eintrag = {"pw": LPW, "id": "uuid-alice", "email": "alice@corp.example"}
a_m.ldap = _Verzeichnis({"alice": _alice_eintrag, "alice@corp.example": _alice_eintrag})
_login(TestClient(ap_m), "alice", LPW)
_alice_m = a_m.store.get_user_by_name("alice")["id"]
_reg_m = a_m.create_user("mallory", password=MPW, email="alice@corp.example")
for _ in range(10):
    for _ in range(4):
        _login(TestClient(ap_m, client=("203.0.113.66", 1)), "alice@corp.example", f"falsch-falsch-1-{next(_FALSCH)}")
    _login(TestClient(ap_m, client=("203.0.113.66", 1)), "alice@corp.example", MPW)
_treffer_m = _login(TestClient(ap_m, client=("203.0.113.66", 1)), "alice@corp.example", LPW)
# (Mutation probe: switch off the check against `nur_konto` → 303, session of Alice → red.)
r.check("p1-d (C): a local account with the directory address of another person — their LDAP password "
        "opens no session under the address",
        bool(_reg_m) and _treffer_m.status_code == 401 and _sitzung_von(a_m, _treffer_m) is None,
        f"Registrierung {_reg_m}, HTTP {_treffer_m.status_code}")
r.check("… under her name Alice continues to sign in (counter-check)",
        _sitzung_von(a_m, _login(TestClient(ap_m), "alice", LPW)) == _alice_m)

# ── B2-8: PIN as first factor — explicitly allowed, with its own limit ──────────────────
auth, app = _app(pin_enabled=True)


@app.get("/allgemein")
def _allgemein(user=Depends(auth.require())):
    return {"ok": True}


@app.get("/detail")
def _detail(user=Depends(auth.require(factors=["pin", "password"]))):
    return {"ok": True}


pin_uid = auth.create_user("pinnutzer", password=PW)
auth.set_pin(pin_uid, "4711")
cp = TestClient(app)
seite = cp.get("/auth/login")
r.check("B2-8: the login page offers the PIN as first factor (pin_login, default)",
        "/auth/pin" in seite.text, "no PIN route on the login page")
cp.post("/auth/pin", data={"username": "pinnutzer", "pin": "4711"}, follow_redirects=False)
r.check("… with the PIN alone one reaches the general page",
        cp.get("/allgemein", follow_redirects=False).status_code == 200)
r.check("… the detail page demands more (chain pin → password per route)",
        cp.get("/detail", follow_redirects=False).status_code != 200)
_login(cp, "pinnutzer", PW)
r.check("… and opens after the password", cp.get("/detail", follow_redirects=False).status_code == 200)
a_aus, _ = _app(pin_enabled=True, pin_login=False)
r.check("B2-8 configurable: pin_login=False takes the PIN off the login page",
        "/auth/pin" not in TestClient(_).get("/auth/login").text)
reihe = list(auth.all_security())
r.check("B2-8: the PIN attempts are in the panel with the lock settings",
        reihe.index("pin_max_attempts") == reihe.index("account_max_consecutive_failures") + 1
        and reihe.index("account_max_consecutive_failures") == reihe.index("account_attempt_factor") + 1,
        str(reihe[:8]))
for _ in range(auth._sec("pin_max_attempts")):
    TestClient(app).post("/auth/pin", data={"username": "pinnutzer", "pin": "0000"})
gesperrt = TestClient(app).post("/auth/pin", data={"username": "pinnutzer", "pin": "4711"})
r.check("B2-8: after pin_max_attempts misses the PIN path is closed", gesperrt.status_code == 429,
        f"HTTP {gesperrt.status_code}")
r.check("… and the PIN misses count into the series (B2-6)", auth.store.fehlserie("pinnutzer") >= 5)


# ── OIDC helpers: network-free, real callback ─────────────────────────────────────────────
class _Claims(dict):
    def validate(self, *a, **k):
        pass


def _oidc(claims, **cfg):
    auth, app = _app(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe",
                     oidc_client_secret="geheim", **cfg)
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize",
                       "token_endpoint": IDP + "/token", "userinfo_endpoint": IDP + "/userinfo",
                       "jwks_uri": IDP + "/jwks"}
    _setze(auth, claims)
    from tinysesam.oidc import OIDCClient
    auth.oidc.userinfo = lambda at, erwartetes_sub="": OIDCClient.userinfo_pruefen({}, erwartetes_sub)
    return auth, app


def _setze(auth, claims):
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})


def _oidc_login(app):
    c = TestClient(app, raise_server_exceptions=False)
    start = c.get("/auth/oidc/start", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)


# ── F-27: email collision with a local account ───────────────────────────────────────────
a27, app27 = _oidc({"sub": "k-1", "preferred_username": "neu", "email": "lokal@example.com",
                    "email_verified": True})
lokal = a27.create_user("lokal", password=PW, email="lokal@example.com")
antwort = _oidc_login(app27)
r.check("F-27: proven address of a local account → 409, no 500", antwort.status_code == 409,
        f"HTTP {antwort.status_code}")
r.check("… no second account, no link, a line for the operator",
        a27.store.get_user_by_name("neu") is None and not a27.store.get_oidc_user(IDP, "k-1")
        and any(z["event"] == "oidc_ident_taken" for z in a27.store.recent_audit(50)))
a27b, app27b = _oidc({"sub": "k-2", "preferred_username": "neu2", "email": "lokal@example.com",
                      "email_verified": False})
lokal_b = a27b.create_user("lokal", password=PW, email="lokal@example.com")
antwort = _oidc_login(app27b)
neu2 = a27b.store.get_user_by_name("neu2")
r.check("F-27 + H-3: an UNPROVEN foreign address does not collide and takes nothing over",
        antwort.status_code == 303 and neu2 is not None and not neu2["email"]
        and a27b.store.get_user(lokal_b)["email"] == "lokal@example.com",
        f"HTTP {antwort.status_code}")

# ── H-3: an address without proof is not used ────────────────────────────────────────────
a3, app3 = _oidc({"sub": "h3-1", "email": "fremd@example.com", "email_verified": False})
_oidc_login(app3)
konten = [dict(u) for u in a3.store.list_users()]
k3 = konten[0] if konten else None
r.check("H-3: without proof no name from the address, no address in the account, no Remote-Email",
        k3 is not None and k3["username"].startswith("oidc-") and not k3["email"]
        and not a3._forward_response_headers(k3).get("Remote-Email"), str(k3))
a3b, app3b = _oidc({"sub": "h3-2", "email": "belegt@example.com", "email_verified": True})
_oidc_login(app3b)
k3b = a3b.store.get_user_by_name("belegt@example.com")
r.check("… with proof it is used (name, account, Remote-Email)",
        k3b is not None and k3b["email"] == "belegt@example.com" and k3b["email_verified"]
        and a3b._forward_response_headers(k3b).get("Remote-Email") == "belegt@example.com")
a3c, app3c = _oidc({"sub": "h3-3", "email": "entra@example.com"}, oidc_email_verified_default=True)
_oidc_login(app3c)
r.check("… a provider without a claim counts only with the operator's explicit statement",
        a3c.store.get_user_by_name("entra@example.com") is not None)
a3d, app3d = _oidc({"sub": "h3-4", "email": "nein@example.com", "email_verified": False},
                   oidc_email_verified_default=True)
_oidc_login(app3d)
r.check("… an explicit false stays false, even with this statement",
        all(not u["email"] for u in a3d.store.list_users()))
a3e, app3e = _oidc({"sub": "h3-5", "preferred_username": "spaet", "email": "spaet@example.com"})
_oidc_login(app3e)
_setze(a3e, {"sub": "h3-5", "preferred_username": "spaet", "email": "spaet@example.com",
             "email_verified": True})
_oidc_login(app3e)
r.check("H-3: if the provider supplies the proof later, the address enters the account as proven",
        a3e.store.get_user_by_name("spaet")["email"] == "spaet@example.com"
        and a3e.store.get_user_by_name("spaet")["email_verified"])
a3f, app3f = _oidc({"sub": "h3-6", "preferred_username": "spaet2", "email": "vergeben@example.com"})
_oidc_login(app3f)
a3f.create_user("inhaber", password=PW, email="vergeben@example.com")
_setze(a3f, {"sub": "h3-6", "preferred_username": "spaet2", "email": "vergeben@example.com",
             "email_verified": True})
_oidc_login(app3f)
r.check("… unless it now belongs to another account (then it stays without)",
        not a3f.store.get_user_by_name("spaet2")["email"]
        and any(z["event"] == "oidc_email_taken" for z in a3f.store.recent_audit(50)))
for wunsch, belegt, erwartet in (("opfer@example.com", False, "oidc-"), ("opfer@example.com", True, "opfer@example.com"),
                                 ("opfer\uff20example.com", False, "oidc-"), ("opfer\ufe6bexample.com", False, "oidc-"),
                                 ("anderer@example.com", True, "opfer@example.com"), ("klarname", False, "klarname")):
    a3g, app3g = _oidc({"sub": f"h3-pu-{wunsch}-{belegt}", "preferred_username": wunsch,
                        "email": "opfer@example.com", "email_verified": belegt})
    _oidc_login(app3g)
    namen = [u["username"] for u in a3g.store.list_users()]
    r.check(f"H-3: preferred_username={wunsch!r} with {'belegter' if belegt else 'unbelegter'} address → {erwartet}…",
            len(namen) == 1 and namen[0].startswith(erwartet), str(namen))
# (Mutation probes: `belegte_mail = mail` in oidc.py → the first H-3 check red; delete the check for
#  `@` in `preferred_username` → the cases with an address as name red.)

# ── H-5: the IdP takes back what it has given ────────────────────────────────────────────
KARTE = {"admins": "__admin__", "redaktion": "editor"}
a5, app5 = _oidc({"sub": "h5-1", "preferred_username": "idpchef", "groups": ["admins", "redaktion"]},
                 oidc_group_role_map=KARTE)
_oidc_login(app5)
chef = a5.store.get_user_by_name("idpchef")
r.check("H-5: admin group at the IdP → admin flag, noted as “from the IdP” (2)", chef["is_admin"] == 2,
        str(chef["is_admin"]))
_setze(a5, {"sub": "h5-1", "preferred_username": "idpchef", "groups": ["redaktion"]})
_oidc_login(app5)
chef = a5.store.get_user_by_name("idpchef")
r.check("… if the IdP no longer delivers the group, the flag is gone at the next login",
        not chef["is_admin"] and "editor" in a5.user_roles(chef), str(dict(chef)))
r.check("… with a line in the audit log", any(z["event"] == "idp_admin_revoke" for z in a5.store.recent_audit(50)))
hand = a5.create_user("handadmin", password=PW, is_admin=True)
a5.apply_idp_groups(hand, [], KARTE)
r.check("H-5: an admin flag granted by hand is never taken by the IdP", a5.store.get_user(hand)["is_admin"] == 1)
idp_admin = a5.create_user("idpzwei", password=PW)
a5.apply_idp_groups(idp_admin, ["admins"], KARTE)
a5.apply_idp_groups(idp_admin, [], {"redaktion": "editor"})
r.check("… and a mapping without an admin target revokes nothing (it manages no admin right)",
        a5.store.get_user(idp_admin)["is_admin"] == 2)
a5.apply_idp_groups(idp_admin, ["cn=admins,ou=g,dc=x"], {"cn=admins": "__admin__"}, dn=True)
a5.apply_idp_groups(idp_admin, ["cn=andere,ou=g,dc=x"], {"cn=admins": "__admin__"}, dn=True)
r.check("H-5 also applies to LDAP DNs (the same path)", not a5.store.get_user(idp_admin)["is_admin"])
# Finding from the attack on H-5: the panel sends the admin checkbox with every save of the roles
# — `set_admin(True)` silently turned the 2 into a 1, and the revocation never worked again.
a5p, app5p = _oidc({"sub": "h5-p", "preferred_username": "panelfall", "groups": ["admins"]},
                   oidc_group_role_map=KARTE)
_oidc_login(app5p)
_pf = a5p.store.get_user_by_name("panelfall")
a5p.create_user("chefin", password=PW, is_admin=True)
cpan = TestClient(app5p)
cpan.post("/auth/login", data={"username": "chefin", "password": PW}, follow_redirects=False)
gespeichert = cpan.post(f"/auth/admin/api/users/{_pf['id']}/roles", json={"roles": ["editor"], "is_admin": True})
r.check("H-5: saving roles in the panel leaves an IdP admin flag as it is (2)",
        gespeichert.status_code == 200 and a5p.store.get_user(_pf["id"])["is_admin"] == 2,
        f"HTTP {gespeichert.status_code}, is_admin={a5p.store.get_user(_pf['id'])['is_admin']}")
_setze(a5p, {"sub": "h5-p", "preferred_username": "panelfall", "groups": []})
_oidc_login(app5p)
r.check("… and the next login without admin group takes it", not a5p.store.get_user(_pf["id"])["is_admin"])
_normal = a5p.create_user("normalo", password=PW)
cpan.post(f"/auth/admin/api/users/{_normal}/roles", json={"roles": [], "is_admin": True})
r.check("… a checkbox the operator newly sets stays a 1 (by hand)",
        a5p.store.get_user(_normal)["is_admin"] == 1)
# (Mutation probes: delete the `elif` branch in apply_idp_groups → "the flag is gone" red;
#  `u["is_admin"] == 2` → `u["is_admin"]` → "by hand … never" red; delete the condition
#  "only on real change" in admin.py → "leaves an IdP admin flag as it is" red.)

# ── G6: after the IdP revokes the last admin the allowlist does not open again ──────────
# Measured before the fix: after the revocation the allowlist person was admin again in the SAME login — as
# "by hand" (1) and first owner, whom no provider revokes any more (`maybe_promote_admin` via
# `apply_factor`, because at that moment there was no admin).
_C6 = {"sub": "g6-1", "preferred_username": "chef6", "email": "chef6@example.com", "email_verified": True}
_LISTE6 = ["chef6@example.com", "vize6@example.com"]
a6, app6 = _oidc({**_C6, "groups": ["admins"]}, oidc_group_role_map=KARTE, admin_identifiers=_LISTE6)
_oidc_login(app6)
_chef6 = a6.store.get_user_by_name("chef6")
r.check("G6: admin group at the IdP → admin from the IdP (2), no owner", (_chef6["is_admin"], _chef6["is_owner"]) == (2, 0),
        str(dict(_chef6)))
_vize6 = a6.create_user("vize6", password=PW, email="vize6@example.com")
_setze(a6, {**_C6, "groups": []})
_err6 = io.StringIO()
with redirect_stderr(_err6):
    _oidc_login(app6)
_chef6 = a6.store.get_user_by_name("chef6")
_audit6 = [(z["event"], z["username"], z["detail"]) for z in a6.store.recent_audit(50)]
r.check("G6: the IdP takes the last admin — the allowlist does NOT promote again in the same login",
        (_chef6["is_admin"], _chef6["is_owner"]) == (0, 0), str(dict(_chef6)))
r.check("… with line admin_bootstrap_denied after_idp_withdrawal, without admin_bootstrap",
        ("admin_bootstrap_denied", "chef6", "after_idp_withdrawal") in _audit6
        and not any(e == "admin_bootstrap" for e, _, _ in _audit6), str(_audit6[:6]))
# stderr is a buffer here, not a console (as in the container) — the token therefore goes to
# `<db_path>.claim` (T-17), not to stderr; `tests/test_operations_findings.py` (b) measures both paths.
_datei6 = a6.cfg.db_path + ".claim"
_tok6 = Path(_datei6).read_text(encoding="utf-8").strip() if os.path.exists(_datei6) else ""
r.check("… and the one-time token goes to the operator immediately (not only at the next start) — "
        "without a console into <db_path>.claim, not onto stderr",
        bool(_tok6) and _tok6 == a6.admin_claim_token() and _tok6 not in _err6.getvalue(),
        f"{_datei6} {bool(_tok6)} {_err6.getvalue()[-200:]}")
with redirect_stderr(io.StringIO()):
    _oidc_login(app6)
r.check("… the next login does not promote either", not a6.store.get_user_by_name("chef6")["is_admin"])
with redirect_stderr(io.StringIO()):
    _login(TestClient(app6), "vize6", PW)
r.check("… and no other allowlist account (the marker applies to the instance)",
        (a6.store.get_user(_vize6)["is_admin"], a6.store.get_user(_vize6)["is_owner"]) == (0, 0)
        and any(z["event"] == "admin_bootstrap_denied" and z["username"] == "vize6"
                for z in a6.store.recent_audit(20)), str(dict(a6.store.get_user(_vize6))))
_chef6 = a6.store.get_user_by_name("chef6")
r.check("G6: the emergency path remains — the one-time token makes admin and owner",
        a6._consume_admin_claim(a6.admin_claim_token(), _chef6)
        and (a6.store.get_user(_chef6["id"])["is_admin"], a6.store.get_user(_chef6["id"])["is_owner"]) == (1, 1))
# Counter-checks: the marker arises only if really no admin remains, and disturbs neither the
# fresh instance nor the path from demo into operation (there purge_demo deletes the last admin).
a6h, app6h = _oidc({**_C6, "sub": "g6-h", "groups": ["admins"]}, oidc_group_role_map=KARTE,
                   admin_identifiers=_LISTE6)
_oidc_login(app6h)
a6h.create_user("handchef6", password=PW, is_admin=True)
_setze(a6h, {**_C6, "sub": "g6-h", "groups": []})
_oidc_login(app6h)
r.check("G6: if the IdP revokes an admin while an admin by hand remains, no marker arises",
        not a6h.store.get_user_by_name("chef6")["is_admin"]
        and a6h.store.get_setting("allowlist_nach_idp_entzug") is None)
a6f, app6f = _app(admin_identifiers=_LISTE6)
_f6 = a6f.create_user("vize6", password=PW, email="vize6@example.com")
_login(TestClient(app6f), "vize6", PW)
r.check("G6: fresh instance — the first allowlist login becomes admin and owner",
        (a6f.store.get_user(_f6)["is_admin"], a6f.store.get_user(_f6)["is_owner"]) == (1, 1))
_db6d = str(Path(tempfile.mkdtemp()) / "t.db")
with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
    TinySesam(TinySesamConfig(db_path=_db6d, cookie_secure=False, demo_mode=True))
    a6d, app6d = _app(db_path=_db6d, admin_identifiers=_LISTE6)
_d6 = a6d.create_user("vize6", password=PW, email="vize6@example.com")
_login(TestClient(app6d), "vize6", PW)
r.check("G6: demo → operation (purge_demo deletes the demo admin): the allowlist applies",
        a6d.store.get_user_by_name("demoadmin") is None
        and (a6d.store.get_user(_d6)["is_admin"], a6d.store.get_user(_d6)["is_owner"]) == (1, 1),
        str(dict(a6d.store.get_user(_d6))))
# (Mutation probes, run individually: switch off the check of the marker in `maybe_promote_admin`
#  → "does NOT promote again", "next login", "no other allowlist account" red;
#  delete the setting in the revocation branch → the same red; delete `if not self.admin_exists()` →
#  "no marker" red; the marker per account instead of per instance → "no other allowlist account" red;
#  delete the token output → "goes to the operator immediately" red.)

# ── F-05: inactivity timeout ──────────────────────────────────────────────────────────────
auth_i, app_i = _app()


@app_i.get("/drin")
def _drin(user=Depends(auth_i.require())):
    return {"ok": True}


r.check("F-05: default 8 h inactivity without “Stay signed in”, with it: off",
        auth_i.store.leerlauf_sek == (8 * 3600, 0), str(auth_i.store.leerlauf_sek))
auth_i.create_user("ruhig", password=PW)
ci = TestClient(app_i)
ci.post("/auth/login", data={"username": "ruhig", "password": PW}, follow_redirects=False)   # without remember
r.check("… freshly signed in one gets in", ci.get("/drin", follow_redirects=False).status_code == 200)
auth_i.store._exec("UPDATE session SET zuletzt = zuletzt - 8 * 3600 - 5")
r.check("… after 8 h without a request the session is gone (not just rejected, deleted)",
        ci.get("/drin", follow_redirects=False).status_code != 200
        and auth_i.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0)
ci2 = TestClient(app_i)
ci2.post("/auth/login", data={"username": "ruhig", "password": PW, "remember": "1"}, follow_redirects=False)
auth_i.store._exec("UPDATE session SET zuletzt = zuletzt - 30 * 86400")
r.check("… with “Stay signed in” only the absolute lifetime counts (default)",
        ci2.get("/drin", follow_redirects=False).status_code == 200)
auth_j, app_j = _app(session_idle_minutes_remember=60)


@app_j.get("/drin")
def _drin_j(user=Depends(auth_j.require())):
    return {"ok": True}


auth_j.create_user("ruhig", password=PW)
cj = TestClient(app_j)
cj.post("/auth/login", data={"username": "ruhig", "password": PW, "remember": "1"}, follow_redirects=False)
cj.get("/drin")
_vorher = auth_j.store._one("SELECT zuletzt FROM session")["zuletzt"]
cj.get("/drin")
r.check("F-05: a second request in the same minute does not write (no lock per request)",
        auth_j.store._one("SELECT zuletzt FROM session")["zuletzt"] == _vorher)
auth_j.store._exec("UPDATE session SET zuletzt = zuletzt - 61 * 60")
r.check("F-05 configurable: also for “Stay signed in” (here 60 min)",
        cj.get("/drin", follow_redirects=False).status_code != 200)
auth_j.create_user("aktiv", password=PW)
ck = TestClient(app_j)
ck.post("/auth/login", data={"username": "aktiv", "password": PW, "remember": "1"}, follow_redirects=False)
auth_j.store._exec("UPDATE session SET zuletzt = zuletzt - 50 * 60, created_at = created_at - 50 * 60 "
                   "WHERE user_id = (SELECT id FROM users WHERE username='aktiv')")
ck.get("/drin")                                              # activity resets the clock
auth_j.store._exec("UPDATE session SET zuletzt = zuletzt - 50 * 60 "
                   "WHERE user_id = (SELECT id FROM users WHERE username='aktiv')")
r.check("F-05: whoever is active stays in (50 + 50 min, but never 60 in one stretch)",
        ck.get("/drin", follow_redirects=False).status_code == 200)
# (Mutation probes: delete the idle check in `get_session` → "after 8 h … gone" red; delete the
#  write-back of `zuletzt` → "whoever is active stays in" red.)

# The choice survives the completion of a chain: password (with checkbox) → TOTP creates a NEW full
# session (privilege change, new token); `_nachfolger` carries the choice over. Without it every
# "Stay signed in" session with a second factor would silently fall back to the 8-h limit.
import time as _uhr_k  # noqa: E402

import pyotp as _pyotp  # noqa: E402
auth_k, app_k = _app(login_chain=["password", "totp"])


@app_k.get("/drin")
def _drin_k(user=Depends(auth_k.require())):
    return {"ok": True}


uid_k = auth_k.create_user("zweifach", password=PW)
_geheim_k = auth_k.totp_begin(uid_k)["secret"]
auth_k.totp_confirm(uid_k, _pyotp.TOTP(_geheim_k).at(_uhr_k.time() - 30))
ckk = TestClient(app_k)
ckk.post("/auth/login", data={"username": "zweifach", "password": PW, "remember": "1"}, follow_redirects=False)
_halb_k = auth_k.store._one("SELECT token_hash, bleiben_gewaehlt FROM session")
ckk.post("/auth/totp", data={"code": _pyotp.TOTP(_geheim_k).now(), "next": "/"}, follow_redirects=False)
_voll_k = auth_k.store._all("SELECT token_hash, bleiben_gewaehlt, mfa_ok FROM session")
r.check("F-05: “Stay signed in” survives the second factor (new full session carries the choice)",
        _halb_k["bleiben_gewaehlt"] == 1 and len(_voll_k) == 1
        and _voll_k[0]["token_hash"] != _halb_k["token_hash"] and _voll_k[0]["bleiben_gewaehlt"] == 1,
        str([dict(z) for z in _voll_k]))
auth_k.store._exec("UPDATE session SET zuletzt = zuletzt - 30 * 86400")
r.check("… and so after password + TOTP still only the absolute lifetime applies",
        ckk.get("/drin", follow_redirects=False).status_code == 200)
# (Mutation probe: delete the transfer in `_nachfolger` → both red.)

# ── Limits a–e from the integration attack (PO: build) ─────────────────────────────────
import re as _re  # noqa: E402
import pyotp  # noqa: E402

# (a) A complete sign-in clears only failed attempts from the creation of the account.
auth_a8, app_a8 = _app()
for _ in range(3):
    auth_a8._record_login("vorher@example.com", "198.51.100.20", False, "password")
auth_a8.store._exec("UPDATE login_attempt SET ts = ts - 3600")
uid_a8 = auth_a8.create_user("neukonto", password=PW, email="vorher@example.com")
_login(TestClient(app_a8), "neukonto", PW)
r.check("Limit a: failed attempts under the address from BEFORE the creation remain after the first login",
        auth_a8.store.count_fails(0, username="vorher@example.com") == 3,
        str(auth_a8.store.count_fails(0, username="vorher@example.com")))
auth_a8._record_login("neukonto", "198.51.100.21", False, "password")
_login(TestClient(app_a8), "neukonto", PW)
r.check("… it clears the account's own (after the creation) as before",
        auth_a8.store.count_fails(0, username="neukonto") == 0)

# (b) The panel distinguishes the two locks.
auth_b8, app_b8 = _app()
auth_b8.create_user("panelchef", password=PW, is_admin=True)
wartet = auth_b8.create_user("wartet", password=PW)
betr = auth_b8.create_user("betreiber-gesperrt", password=PW)
auth_b8.store.set_disabled(wartet, True)
auth_b8.store.set_disabled(betr, True, durch_betreiber=True)
cb8 = TestClient(app_b8)
_login(cb8, "panelchef", PW)
liste = {u["username"]: u for u in cb8.get("/auth/admin/api/users").json()}
r.check("Limit b: the panel names the reason for the lock (confirmation/app vs. operator)",
        liste["wartet"]["disabled_by"] == "confirmation" and liste["betreiber-gesperrt"]["disabled_by"] == "operator"
        and liste["panelchef"]["disabled_by"] is None, str({k: v["disabled_by"] for k, v in liste.items()}))

# (c) The audit searches run via an index.
_plan = auth_b8.store.db.execute(
    "EXPLAIN QUERY PLAN SELECT id FROM audit WHERE event IN ('signup','signup_taken') "
    "AND lower(username) = lower(?) AND ts BETWEEN ? AND ?", ("x", 1, 2)).fetchall()
r.check("Limit c: `anlage_grenze` searches via the index instead of through the whole audit log",
        any("idx_audit_name_ts" in str(tuple(z)) for z in _plan), str([tuple(z) for z in _plan]))

# (d) Chain password → totp → pin with mandatory enrollment: the offer to end the other sessions
#     is redeemed as soon as the chain is complete.
auth_d8, app_d8 = _app(login_chain=["password", "totp", "pin"], pin_enabled=True)
uid_d8 = auth_d8.create_user("kette", password=PW)
auth_d8.set_pin(uid_d8, "4812")
alt_token = auth_d8.store.create_session(uid_d8, 3600, True, "password")   # the lost device
cd8 = TestClient(app_d8)
_login(cd8, "kette", PW)
_seite = cd8.post("/auth/totp/setup/start", data={"next": "/"})
_geheim = _re.search(r"secret=([A-Z2-7]+)", _seite.text) or _re.search(r"\b([A-Z2-7]{32})\b", _seite.text)
_bestaetigt = cd8.post("/auth/totp/setup", data={"code": pyotp.TOTP(_geheim.group(1)).now(), "next": "/"}).json()
r.check("Limit d: the enrollment in the middle of the chain reports the other sessions (other_sessions_after)",
        _bestaetigt.get("ok") and _bestaetigt.get("other_sessions_after") == 1, str(_bestaetigt))
_vermerk = cd8.post("/auth/sessions/revoke-after-login", json={})
r.check("… the consent is noted, but nothing is ended yet",
        _vermerk.status_code == 200 and auth_d8.store.get_session(alt_token) is not None)
cd8.post("/auth/pin", data={"username": "kette", "pin": "4812"}, follow_redirects=False)   # half session: with name
r.check("… and with the last factor (PIN) the other sessions end",
        auth_d8.store.get_session(alt_token) is None and cd8.get("/auth/me").status_code == 200)
auth_v8, app_v8 = _app()                                      # without chain: password = full session
auth_v8.create_user("voll", password=PW)
cvoll = TestClient(app_v8)
_login(cvoll, "voll", PW)
r.check("… a full session cannot set the note (that is what /auth/sessions/revoke is for)",
        cvoll.post("/auth/sessions/revoke-after-login", json={}).status_code in (400, 401))

# (e) Revoking API keys notifies the owner.
auth_e8, app_e8 = _app()
ereignisse = []
auth_e8.on_security_event = lambda ereignis, konto, details: ereignisse.append((ereignis, details))
uid_e8 = auth_e8.create_user("keyhalter", password=PW)
k1 = auth_e8.create_api_key(uid_e8, name="ci")
auth_e8.revoke_api_key(k1["id"])
auth_e8.revoke_api_key(k1["id"])                              # twice: only one event
auth_e8.create_api_key(uid_e8, name="a")
auth_e8.create_api_key(uid_e8, name="b")
auth_e8._keys_widerrufen(uid_e8, "sessions_revoked")
namen = [e for e, _ in ereignisse]
r.check("Limit e: a single revocation reports api_key_revoked (exactly once)",
        namen.count("api_key_revoked") == 1, str(namen))
r.check("… a collective one reports api_keys_revoked with count",
        ("api_keys_revoked", {"count": 2, "reason": "sessions_revoked"}) in ereignisse, str(ereignisse))
chef_e8 = auth_e8.create_user("chef-e8", password=PW, is_admin=True)
auth_e8.create_api_key(uid_e8, name="c")
ce8 = TestClient(app_e8)
_login(ce8, "chef-e8", PW)
ce8.post(f"/auth/admin/api/users/{uid_e8}/disable", json={"disabled": True})
r.check("… also when locking in the panel", ("api_keys_revoked", {"count": 1, "reason": "account_disabled"}) in ereignisse,
        str(ereignisse[-2:]))
# (Mutation probes: delete `seit=since` in `lift_lockout` → (a) red; fix `disabled_by` to
#  None → (b) red; delete index → (c) red; `_andere_nach_abschluss` empty → (d) red;
#  delete `security_event` in `_keys_widerrufen` → (e) red.)

# ── B1-12 / ASVS 6.3.8: registration reveals no addresses (not even in the runtime) ─────
def _reg_app():
    a, app = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                  login_identifier="email")
    a.set_mailer(lambda to, betreff, text, html=None: None)
    return a, app


a638, app638 = _reg_app()
a638.create_user("vergeben@example.com", password=PW, email="vergeben@example.com")
_zaehler = {"n": 0}
_orig_exec = a638.store._exec


def _zaehlend(sql, args=()):
    _zaehler["n"] += 1
    return _orig_exec(sql, args)


a638.store._exec = _zaehlend
c638 = TestClient(app638)
_zaehler["n"] = 0
frei = c638.post("/auth/register", data={"email": "frei@example.com", "password": FUENFZEHN + "x"})
_n_frei = _zaehler["n"]
_zaehler["n"] = 0
vergeben = c638.post("/auth/register", data={"email": "vergeben@example.com", "password": FUENFZEHN + "x"})
_n_vergeben = _zaehler["n"]
a638.store._exec = _orig_exec
r.check("ASVS 6.3.8: free and taken address respond the same (status and page)",
        frei.status_code == vergeben.status_code == 200
        and _re.sub(r"nonce=\"[^\"]+\"", "", frei.text) == _re.sub(r"nonce=\"[^\"]+\"", "", vergeben.text),
        f"{frei.status_code}/{vergeben.status_code}")
r.check("… and do the same work in the request (equally many writes — no timing oracle)",
        _n_frei == _n_vergeben, f"frei {_n_frei}, vergeben {_n_vergeben}")
_platz = [u for u in a638.store.list_users() if str(u["username"]).startswith("reserviert-")]
r.check("… the placeholder is locked, carries no address and disappears with gc()",
        len(_platz) == 1 and _platz[0]["disabled"] and not _platz[0]["email"])
from tinysesam import config_check as _kp  # noqa: E402
_, _w638 = _kp.check_config(TinySesamConfig(db_path=":memory:", base_url="https://app.example", allow_signup=True,
                                      signup_require_email=True))
r.check("… without confirmation this does not work — the configuration check says so (6.3.8)",
        any("6.3.8" in w for w in _w638), str(_w638)[:200])
# (Mutation probe: only `hash_password` instead of placeholder in the taken branch again → writes red.)

# ── B1-12 / ASVS 6.3.5: notice to the owner when their account is locked ──────────────────
def _hinweis_app(**cfg):
    a, app = _app(**cfg)
    post = []
    a.set_mailer(lambda to, betreff, text, html=None: post.append((to, betreff, text)))
    return a, app, post


a635, app635, post635 = _hinweis_app()
a635.create_user("inhaberin", password=PW, email="inhaberin@example.com")
for _ in range(a635._sec("max_login_attempts") + 2):
    _login(TestClient(app635), "inhaberin", f"falsch-falsch-falsch-{next(_FALSCH)}")
a635._hinweis_ausgang.abwarten()
r.check("ASVS 6.3.5: with configured mail delivery the owner gets a notice (default on, opt-out)",
        len(post635) == 1 and post635[0][0] == "inhaberin@example.com", str(post635))
r.check("… the notice carries no link (there is no base an attacker could bend)",
        post635 and "://" not in post635[0][2], post635[0][2][:120] if post635 else "")
r.check("… exactly one per lock window, not one per rejected attempt",
        len(post635) == 1 and any(z["event"] == "lockout_notice" for z in a635.store.recent_audit(50)))
for _ in range(a635._sec("max_login_attempts") + 2):
    _login(TestClient(app635), "niemand", f"falsch-falsch-falsch-{next(_FALSCH)}")
a635._hinweis_ausgang.abwarten()
r.check("… an unknown name triggers nothing (and the same happens in the request)", len(post635) == 1)
a635u, app635u, post635u = _hinweis_app()
_u = a635u.create_user("unbelegt", password=PW, email="unbelegt@example.com")
a635u.store.set_email_verified(_u, False)
for _ in range(a635u._sec("max_login_attempts") + 2):
    _login(TestClient(app635u), "unbelegt", f"falsch-falsch-falsch-{next(_FALSCH)}")
a635u._hinweis_ausgang.abwarten()
r.check("… nothing goes to an UNPROVEN address (H-3)", post635u == [], str(post635u))
a635o, app635o, post635o = _hinweis_app(notify_login_failures=False)
a635o.create_user("still", password=PW, email="still@example.com")
for _ in range(a635o._sec("max_login_attempts") + 2):
    _login(TestClient(app635o), "still", f"falsch-falsch-falsch-{next(_FALSCH)}")
a635o._hinweis_ausgang.abwarten()
r.check("… opt-out: notify_login_failures=False sends nothing", post635o == [], str(post635o))
# (Mutation probes: do not call `_sperrhinweis` in `_abgewiesen` → first check red; delete the
#  throttle → "exactly one" red; delete `_beleg_am_konto` → "UNPROVEN" red.)

# ── H-14/H-15: TOTP secrets encrypted at rest (mandatory) ────────────────────────────────
import base64 as _b64  # noqa: E402
import os as _os  # noqa: E402
import stat as _stat  # noqa: E402

a14, app14 = _app()
u14 = a14.create_user("totpnutzer", password=PW)
geheim14 = a14.totp_begin(u14)["secret"]
roh14 = a14.store._one("SELECT secret FROM totp_cred WHERE user_id=?", (u14,))["secret"]
r.check("H-14/15: in the database the TOTP secret is stored encrypted, not in plaintext",
        roh14.startswith("v1:") and geheim14 not in roh14, roh14[:20])
r.check("… and signing in with it works (setup with a real code)",
        a14.totp_confirm(u14, pyotp.TOTP(geheim14).now()))
_keydatei = a14.cfg.db_path + ".key"
r.check("… without a setting the key lies next to the database, readable only by the owner (0600)",
        _os.path.isfile(_keydatei) and _stat.S_IMODE(_os.stat(_keydatei).st_mode) == 0o600)

# Existing data: a plaintext secret is encrypted at startup (silent lift).
_pfad14 = a14.cfg.db_path
a14.store._exec("UPDATE totp_cred SET secret=? WHERE user_id=?", (geheim14, u14))   # as before 0.21
a14.store.db.close()
a14b, _ = _app(db_path=_pfad14)
roh14b = a14b.store._one("SELECT secret FROM totp_cred WHERE user_id=?", (u14,))["secret"]
r.check("H-14/15: a plaintext secret from before is encrypted at startup",
        roh14b.startswith("v1:") and a14b.store.get_totp(u14)["secret"] == geheim14)
a14b.store.db.close()

# Wrong key → startup aborts instead of silently letting every TOTP sign-in fail.
_os.environ["TINYSESAM_SECRETS_KEY"] = _b64.b64encode(_os.urandom(32)).decode()
try:
    _app(db_path=_pfad14)
    _falsch = False
except ConfigError:
    _falsch = True
finally:
    del _os.environ["TINYSESAM_SECRETS_KEY"]
r.check("H-14/15: a key that does not fit aborts startup (ConfigError)", _falsch)

# Precedence: environment before file before "next to the database"; a broken value is an error.
_datei14 = str(Path(tempfile.mkdtemp()) / "schluessel")
with open(_datei14, "w") as _f:
    _f.write(_b64.b64encode(_os.urandom(32)).decode())
a14c, _ = _app(secrets_key_file=_datei14)
r.check("… secrets_key_file is taken, then no file next to the database is created",
        a14c._schluessel_herkunft == "file" and not _os.path.exists(a14c.cfg.db_path + ".key"))
with open(_datei14, "w") as _f:
    _f.write("zu-kurz")
try:
    _app(secrets_key_file=_datei14)
    _kaputt = False
except ConfigError:
    _kaputt = True
r.check("… a broken key (not Base64 of 32 bytes) is an error, no silent replacement", _kaputt)
# (Mutation probes: store `set_totp` unencrypted → first check red; remove the key probe
#  in `geheimnisse_heben` → "aborts startup" red; remove the lifting → "plaintext …
#  is encrypted at startup" red.)



def _jetzt_minus(auth):
    """Seconds until the next re-check of the (single) OIDC session."""
    import time as _t
    z = auth.store._one("SELECT geprueft_at FROM oidc_sitzung")
    return int(z["geprueft_at"]) + int(auth.cfg.oidc_session_refresh_minutes) * 60 - int(_t.time())


# ── 4a: revocation follows the provider (refresh token every N minutes) ─────────────────────
a4a, app4a = _oidc({"sub": "r-1", "preferred_username": "refresher", "groups": ["admins"]},
                   oidc_group_role_map=KARTE)
a4a.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
    _Claims({"sub": "r-1", "preferred_username": "refresher", "groups": ["admins"], "nonce": nonce}),
    {"access_token": "at", "refresh_token": "rt-1"})
_antworten = []
_gerufen = []


def _refresh(rt, sub):
    _gerufen.append((rt, sub))
    return _antworten.pop(0)


a4a.oidc.refresh = _refresh
c4a = TestClient(app4a, raise_server_exceptions=False)
_start = c4a.get("/auth/oidc/start", follow_redirects=False)
_st = parse_qs(urlparse(_start.headers["location"]).query)["state"][0]
c4a.get(f"/auth/oidc/callback?code=x&state={_st}", follow_redirects=False)
_roh4a = a4a.store._one("SELECT refresh FROM oidc_sitzung")
r.check("4a: the refresh token is stored with the session, encrypted",
        _roh4a is not None and _roh4a["refresh"].startswith("v1:") and "rt-1" not in _roh4a["refresh"])
r.check("… within the period TinySesam does not ask the provider",
        c4a.get("/auth/me").status_code == 200 and _gerufen == [])


def _altern():
    a4a.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")


_uid4a = a4a.store.get_user_by_name("refresher")["id"]
_altern()
_antworten.append(("ok", {"sub": "r-1", "groups": ["admins"]}, {"refresh_token": "rt-2"}))
_erste = c4a.get("/auth/me").status_code
a4a._oidc_ausgang.abwarten()                                  # the exchange happens in the background (finding 6)
r.check("4a: after the period it is exchanged; the provider says yes → the session stays",
        _erste == 200 and c4a.get("/auth/me").status_code == 200 and _gerufen == [("rt-1", "r-1")])
r.check("… a newly issued refresh token replaces the old one (rotation)",
        a4a.store.get_oidc_sitzung(a4a.store._one("SELECT token_hash FROM oidc_sitzung")["token_hash"])["refresh"] == "rt-2")
_altern()
_antworten.append(("ok", {"sub": "r-1", "groups": []}, {}))
c4a.get("/auth/me")
a4a._oidc_ausgang.abwarten()
r.check("4a + H-5: if the provider takes away the admin group, the flag is gone within the period — not only at login",
        not a4a.store.get_user(_uid4a)["is_admin"])
_altern()
_antworten.append(("ok", {"sub": "r-1"}, {}))                   # no groups claim
a4a.set_roles(_uid4a, ["editor"])
c4a.get("/auth/me")
a4a._oidc_ausgang.abwarten()
r.check("… if the groups claim is missing entirely, the roles stay (missing ≠ no groups)",
        "editor" in a4a.user_roles(a4a.store.get_user(_uid4a)))
_altern()
_antworten.append(("fehler", {}, {"error": "ConnectError"}))
c4a.get("/auth/me")
a4a._oidc_ausgang.abwarten()
r.check("4a: if the provider is unreachable, the session stays (an outage signs nobody out)",
        c4a.get("/auth/me").status_code == 200)
r.check("… and it is retried within a minute, not only after the full period",
        _jetzt_minus(a4a) <= 15 * 60 - 60 + 5)
_altern()
_antworten.append(("abgelehnt", {}, {"error": "invalid_grant"}))
c4a.get("/auth/me")
a4a._oidc_ausgang.abwarten()
r.check("4a: if the provider refuses (locked, deleted, withdrawn), the session is gone",
        c4a.get("/auth/me").status_code == 401
        and a4a.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0
        and any(z["event"] == "oidc_revoked" for z in a4a.store.recent_audit(20)))
a4b, app4b = _oidc({"sub": "r-2", "preferred_username": "ohne"}, oidc_session_refresh_minutes=0)
a4b.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
    _Claims({"sub": "r-2", "preferred_username": "ohne", "nonce": nonce}),
    {"access_token": "at", "refresh_token": "rt-x"})
_oidc_login(app4b)
r.check("4a configurable: oidc_session_refresh_minutes=0 stores nothing",
        a4b.store._one("SELECT COUNT(*) AS n FROM oidc_sitzung")["n"] == 0)
# (Mutation probes: `_oidc_nachpruefen` always True → "session gone" red; remove the group re-evaluation
#  → "flag … gone" red; remove `in info` → "missing ≠ no groups" red; remove the
#  retry within a minute → "within a minute" red.)

# ── Findings from the attack on the second round (4a, key, idle, notice) ─────────────────────
import threading as _th  # noqa: E402
import time as _zeit  # noqa: E402


def _oidc_mit_refresh(sub, claims=None, **cfg):
    extra = dict(claims or {})
    a, app = _oidc({"sub": sub, "preferred_username": sub, **extra}, **cfg)
    a.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({"sub": sub, "preferred_username": sub, **extra, "nonce": nonce}),
        {"access_token": "at", "refresh_token": "rt-" + sub})
    c = TestClient(app, raise_server_exceptions=False)
    st = parse_qs(urlparse(c.get("/auth/oidc/start", follow_redirects=False).headers["location"]).query)["state"][0]
    c.get(f"/auth/oidc/callback?code=x&state={st}", follow_redirects=False)
    return a, app, c


# Finding 5: parallel requests after the period → exactly ONE exchange (rotation at the provider).
a5r, _, c5r = _oidc_mit_refresh("parallel")
_tausche = []
a5r.oidc.refresh = lambda rt, sub: (_tausche.append(rt) or ("ok", {"sub": sub}, {}))
a5r.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
_s5 = a5r.store._one("SELECT * FROM session")
for _ in range(4):
    a5r._oidc_nachpruefen(_s5)
a5r._oidc_ausgang.abwarten()
r.check("Finding 5: four requests after the period exchange the refresh token exactly once", len(_tausche) == 1,
        str(_tausche))

# Finding 6: a hanging provider does not hold up the request.
a6r, _, c6r = _oidc_mit_refresh("haengt")
a6r.oidc.refresh = lambda rt, sub: (_zeit.sleep(1.5), ("ok", {"sub": sub}, {}))[1]
a6r.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
_t0 = _zeit.monotonic()
_st6 = c6r.get("/auth/me").status_code
_dauer = _zeit.monotonic() - _t0
a6r._oidc_ausgang.abwarten()
r.check("Finding 6: the request does not wait for the provider (exchange in the background)",
        _st6 == 200 and _dauer < 1.0, f"{_dauer:.2f}s")

# Finding 7: one row per client — a login via a second client does not overwrite the first.
_h7 = a6r.store._one("SELECT token_hash FROM oidc_sitzung")["token_hash"]
a6r.store.set_oidc_sitzung(_h7, "app-b", "haengt", "rt-b")
r.check("Finding 7: several clients of one session — every row stays and is re-checked",
        {z["client"] for z in a6r.store.get_oidc_sitzungen(_h7)} == {"*", "app-b"})

# Finding 13: nobody asks the provider about a locked account.
a13, _, c13 = _oidc_mit_refresh("gesperrt13")
_t13 = []
a13.oidc.refresh = lambda rt, sub: (_t13.append(rt) or ("ok", {"sub": sub, "groups": ["admins"]}, {}))
a13.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a13.store._exec("UPDATE users SET disabled = 2")
c13.get("/auth/me")
a13._oidc_ausgang.abwarten()
r.check("Finding 13: nothing is exchanged for a locked account (F-17)", _t13 == [], str(_t13))

# Finding 4: a wrong key aborts startup even when there are only refresh tokens.
_pfad4 = a5r.cfg.db_path
a5r.store.db.close()
_os.environ["TINYSESAM_SECRETS_KEY"] = _b64.b64encode(_os.urandom(32)).decode()
try:
    _oidc({"sub": "x"}, db_path=_pfad4)
    _f4 = False
except ConfigError:
    _f4 = True
finally:
    del _os.environ["TINYSESAM_SECRETS_KEY"]
r.check("Finding 4: wrong key + only OIDC refresh tokens → startup aborts", _f4)

# Finding 9: the 8-h limit applies to every session without an EXPLICIT "stay signed in".
a9, app9, c9 = _oidc_mit_refresh("leerlauf9")
a9.store._exec("UPDATE session SET zuletzt = zuletzt - 9 * 3600")
r.check("Finding 9: an OIDC session (persistent, but without choice) ends after 8 h of inactivity",
        c9.get("/auth/me").status_code == 401)

# Finding 10: several workers create the key at the same time — all get the same one.
from tinysesam import vault as _gh  # noqa: E402
_db10 = str(Path(tempfile.mkdtemp()) / "race.db")
_erg10, _fehler10 = [], []


def _laden10():
    try:
        _erg10.append(_gh.load_key(_db10)[0])
    except Exception as e:   # noqa: BLE001
        _fehler10.append(repr(e))


_faeden = [_th.Thread(target=_laden10) for _ in range(24)]
for _f in _faeden:
    _f.start()
for _f in _faeden:
    _f.join()
r.check("Finding 10: 24 simultaneous first starts — no error, a single key",
        not _fehler10 and len(set(_erg10)) == 1 and len(_erg10) == 24, f"{_fehler10[:2]} / {len(set(_erg10))}")

# Finding 11: the throttle of the lock notice lives in the database — an evicted memory key
# (or a second worker) sends no second one.
a11, app11, post11 = _hinweis_app()
a11.create_user("gedrosselt", password=PW, email="gedrosselt@example.com")
a11._sperrhinweis("gedrosselt", "198.51.100.30", "lockout_user")
a11._hinweis_ausgang.abwarten()
a11.rl.allow = lambda *a, **k: True                             # as after the eviction
a11._sperrhinweis("gedrosselt", "198.51.100.31", "lockout_user")
a11._hinweis_ausgang.abwarten()
r.check("Finding 11: even without the memory throttle at most one notice per lock window", len(post11) == 1,
        str(len(post11)))
# (Mutation probes: remove the claim in `_oidc_nachpruefen` → finding 5 red; the exchange
#  synchronous instead of via `_oidc_ausgang` → finding 6 red; remove the audit throttle in `_senden` →
#  finding 11 red; remove `bleiben_gewaehlt` in `get_session` → finding 9 red.)

# ── Finding 8: API keys follow the identity provider (PO decision 2026-09-24) ─────────────
# If the provider says no (4a), the keys of the OIDC account rest; likewise without confirmation within
# `oidc_apikey_confirm_days`. Nothing is deleted — the next sign-in wakes them.
def _erneut_ueber_idp(c):
    st = parse_qs(urlparse(c.get("/auth/oidc/start", follow_redirects=False).headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={st}", follow_redirects=False)


a8, app8, c8 = _oidc_mit_refresh("keyhalter")
uid8 = a8.store.get_user_by_name("keyhalter")["id"]
key8 = a8.create_api_key(uid8, name="backup")["key"]
r.check("Finding 8: the key of an account freshly signed in via the provider is valid",
        a8.verify_api_key(key8)[0] is not None)
a8.oidc.refresh = lambda rt, sub: ("abgelehnt", {}, {"error": "invalid_grant"})
a8.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a8._oidc_nachpruefen(a8.store._one("SELECT * FROM session"))
a8._oidc_ausgang.abwarten()
r.check("Finding 8: after the provider's no the key rests (session gone, key rejected)",
        a8.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0 and a8.verify_api_key(key8)[0] is None)
_zeile8 = a8.store._one("SELECT detail FROM audit WHERE event='api_keys_dormant'")
r.check("… with a row in the audit log (how many keys it affects)",
        _zeile8 is not None and "count=1" in _zeile8["detail"], str(_zeile8 and dict(_zeile8)))
r.check("… nothing is deleted or revoked",
        not a8.store._one("SELECT revoked FROM api_key")["revoked"])
# The no is stored as a NEGATIVE timestamp; a yes only wakes if its question went out afterwards. Here
# the no is five seconds old, the sign-in starts now.
a8.store._exec("UPDATE users SET idp_bestaetigt_at = ? WHERE id=?", (-(int(_zeit.time()) - 5), uid8))
r.check("… and the next sign-in via the provider wakes it again",
        _erneut_ueber_idp(c8).status_code == 303 and a8.verify_api_key(key8)[0] is not None)
# The race: the question went out BEFORE the no (two sessions, two workers), but the yes is
# applied afterwards. It must not overwrite the no.
a8.store.idp_verweigert(uid8)
_frage_vorher = int(_zeit.time()) - 10
r.check("Finding 8: a yes whose question went out BEFORE the no does not wake the keys (race)",
        not a8.store.idp_bestaetigen(uid8, _frage_vorher) and a8.verify_api_key(key8)[0] is None)
a8.store._exec("UPDATE users SET idp_bestaetigt_at = ? WHERE id=?", (-(int(_zeit.time()) - 5), uid8))
r.check("… one whose question went out afterwards does",
        a8.store.idp_bestaetigen(uid8, int(_zeit.time())) and a8.verify_api_key(key8)[0] is not None)

# Period without session (script-only): 30 days default.
a8.store._exec("UPDATE users SET idp_bestaetigt_at = ? WHERE id=?", (int(_zeit.time()) - 29 * 86400, uid8))
_innen8 = a8.verify_api_key(key8)[0] is not None
a8.store._exec("UPDATE users SET idp_bestaetigt_at = ? WHERE id=?", (int(_zeit.time()) - 31 * 86400, uid8))
r.check("Finding 8: without confirmation within 30 days the key rests (29 days: valid, 31: rests)",
        _innen8 and a8.verify_api_key(key8)[0] is None)
a8.cfg.oidc_apikey_confirm_days = 0
_ohne_frist8 = a8.verify_api_key(key8)[0] is not None
a8.store.idp_verweigert(uid8)
r.check("… `oidc_apikey_confirm_days=0` switches off only the period — the no still counts",
        _ohne_frist8 and a8.verify_api_key(key8)[0] is None)
a8.cfg.oidc_apikey_confirm_days = 30

# A yes at the exchange confirms; a group withdrawal is a no.
a8b, app8b, c8b = _oidc_mit_refresh("gruppe8", claims={"groups": ["team"]}, oidc_allowed_groups=["team"])
uid8b = a8b.store.get_user_by_name("gruppe8")["id"]
key8b = a8b.create_api_key(uid8b, name="ci")["key"]
a8b.store._exec("UPDATE users SET idp_bestaetigt_at = 1000 WHERE id=?", (uid8b,))
a8b.oidc.refresh = lambda rt, sub: ("ok", {"sub": sub, "groups": ["team"]}, {})
a8b.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a8b._oidc_nachpruefen(a8b.store._one("SELECT * FROM session"))
a8b._oidc_ausgang.abwarten()
r.check("Finding 8: a yes at the refresh exchange confirms the account (the old state becomes fresh)",
        a8b.store.get_user(uid8b)["idp_bestaetigt_at"] > 1000 and a8b.verify_api_key(key8b)[0] is not None)
a8b.oidc.refresh = lambda rt, sub: ("ok", {"sub": sub, "groups": ["andere"]}, {})
a8b.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a8b._oidc_nachpruefen(a8b.store._one("SELECT * FROM session"))
a8b._oidc_ausgang.abwarten()
r.check("… withdrawal of the allowed group is a no: the key rests",
        a8b.verify_api_key(key8b)[0] is None and a8b.store.get_user(uid8b)["idp_bestaetigt_at"] < 0)

# Accounts without an OIDC binding are not affected — not even with a state that would mean "no".
lokal8 = a8.create_user("lokal8", password=PW)
key8l = a8.create_api_key(lokal8, name="lokal")["key"]
a8.store._exec("UPDATE users SET idp_bestaetigt_at = 0 WHERE id=?", (lokal8,))
r.check("Finding 8: an account without an OIDC binding keeps its key (even with idp_bestaetigt_at=0)",
        a8.verify_api_key(key8l)[0] is not None)

# Existing data: the period starts with the update, exactly once.
_pfad8 = str(Path(tempfile.mkdtemp()) / "bestand8.db")
_alt8 = Store(_pfad8)
_alt8.create_user("bestand-oidc", None, None, False, [], False)
_alt8.link_oidc("https://idp.example", "sub-b", 1)
_alt8.db.execute("ALTER TABLE users DROP COLUMN idp_bestaetigt_at")
_alt8.db.execute("DELETE FROM setting WHERE key='idp_bestand_gesetzt'")   # a 0.20 file does not know it
_alt8.db.commit()
_alt8.db.close()
_neu8 = Store(_pfad8)
_stand8 = _neu8.get_user(1)["idp_bestaetigt_at"]
# Afterwards without state (an account bound by a route without confirmation): a restart
# must NOT grant it a fresh period.
_neu8.db.execute("UPDATE users SET idp_bestaetigt_at = NULL WHERE id=1")
_neu8.db.commit()
_neu8.db.close()
r.check("Finding 8, existing data: the period of an OIDC account starts with the update — and only once",
        _stand8 is not None and abs(_stand8 - int(_zeit.time())) < 60
        and Store(_pfad8).get_user(1)["idp_bestaetigt_at"] is None, f"{_stand8}")
# Abort in the middle of the update: the column is already there (the ALTER is durable immediately), state and
# marker are not. The next start catches up.
_pfad8c = str(Path(tempfile.mkdtemp()) / "abbruch8.db")
_ab8 = Store(_pfad8c)
_ab8.create_user("abbruch-oidc", None, None, False, [], False)
_ab8.link_oidc("https://idp.example", "sub-c", 1)
_ab8.db.execute("DELETE FROM setting WHERE key='idp_bestand_gesetzt'")
_ab8.db.commit()
_ab8.db.close()
r.check("Finding 8, existing data: after an abort (column present, marker not) the next start sets the state",
        Store(_pfad8c).get_user(1)["idp_bestaetigt_at"] is not None)
# (Mutation probes: remove `_key_ruht` in `verify_api_key` → "rests" red; remove `idp_bestaetigen` in the
#  callback → "wakes it again" red; remove the period check → "31: rests" red;
#  remove `_idp_nein` in the group branch → group withdrawal red; remove the binding check →
#  "without OIDC binding" red; the existing-data line at every start → "only once" red.)


# ── 3c · ASVS 6.3.6: the sign-in link needs the second factor when there is one ─────────────
def _link_app(**cfg):
    a, ap = _app(magiclink_enabled=True, **cfg)
    a.set_mailer(lambda *x, **k: True)

    @ap.get("/drin")
    def _drin(user=Depends(a.require())):
        return {"u": user["username"]}
    return a, ap


def _link_login(a, ap, name):
    c = TestClient(ap)
    uid = a.store.get_user_by_name(name)["id"]
    tok = a.create_magic_token("login", user_id=uid, payload={"next": "/drin"})
    return c, c.post(f"/auth/magic/{tok}", follow_redirects=False)


# Classic (no chain), account with passkey only: up to here the link alone signed in fully.
a3c, ap3c = _link_app()
u3c = a3c.create_user("passkey-konto", password=PW, email="pk@example.com")
a3c.store.add_webauthn(u3c, b"cred-3c", b"pub", 0, "[]", "Laptop")
c3c, antw3c = _link_login(a3c, ap3c, "passkey-konto")
r.check("3c: account with passkey — the link alone does not sign in fully (continue to the passkey)",
        antw3c.status_code == 303 and antw3c.headers["location"].startswith(a3c.cfg.login_path)
        and c3c.get("/drin", follow_redirects=False).status_code != 200,
        f"{antw3c.status_code} {antw3c.headers.get('location')}")
# Chain ["magic"] with TOTP: the link satisfied the chain, the authenticator did not count.
a3k, ap3k = _link_app(login_chain=["magic"])
u3k = a3k.create_user("totp-konto", password=PW, email="tk@example.com")
_g3k = a3k.totp_begin(u3k)["secret"]
a3k.totp_confirm(u3k, pyotp.TOTP(_g3k).at(_zeit.time() - 30))
c3k, antw3k = _link_login(a3k, ap3k, "totp-konto")
r.check("3c: chain [\"magic\"], account with TOTP — the TOTP step follows the link",
        antw3k.status_code == 303 and antw3k.headers["location"].startswith("/auth/totp")
        and c3k.get("/drin", follow_redirects=False).status_code != 200,
        f"{antw3k.status_code} {antw3k.headers.get('location')}")
_fertig3k = c3k.post("/auth/totp", data={"code": pyotp.TOTP(_g3k).now(), "next": "/drin"},
                     follow_redirects=False)
r.check("… with the code the sign-in is complete",
        _fertig3k.status_code == 303 and c3k.get("/drin").json() == {"u": "totp-konto"})
a3o, ap3o = _link_app(login_chain=["magic"])
a3o.create_user("ohne-faktor", password=PW, email="of@example.com")
c3o, _ = _link_login(a3o, ap3o, "ohne-faktor")
r.check("3c: an account without a second factor is still signed in by the link alone (C, not D)",
        c3o.get("/drin").json() == {"u": "ohne-faktor"})
a3a, ap3a = _link_app(login_chain=["magic"], magiclink_require_second_factor=False)
u3a = a3a.create_user("totp-a", password=PW, email="ta@example.com")
_g3a = a3a.totp_begin(u3a)["secret"]
a3a.totp_confirm(u3a, pyotp.TOTP(_g3a).at(_zeit.time() - 30))
c3a, _ = _link_login(a3a, ap3a, "totp-a")
r.check("3c configurable: magiclink_require_second_factor=False — the link suffices again (A)",
        c3a.get("/drin").json() == {"u": "totp-a"})
_pw3 = TestClient(ap3k)
_pw3.post("/auth/login", data={"username": "totp-konto", "password": PW, "next": "/drin"},
          follow_redirects=False)
r.check("… other routes stay as they were (password alone in the chain [\"magic\"]: no login)",
        _pw3.get("/drin", follow_redirects=False).status_code != 200)
# (Mutation probes: remove `_link_braucht` in `_session_ok` → the first two red; remove the
#  passkey line → passkey account red; do not read the switch → "configurable" red.)

# G10: the same rule in route chains. Until 2026-09-26 `require(factors=["magic"])` only checked the
# own list — measured: account with TOTP, sign-in link only, global route 401, this route 200.
# The mailbox alone opened it, although `magiclink_require_second_factor` was on.
def _route_app(**cfg):
    a, ap = _link_app(**cfg)

    @ap.get("/r")
    def _r(user=Depends(a.require(factors=["magic"]))):
        return {"u": user["username"]}

    @ap.get("/r2")
    def _r2(user=Depends(a.require(factors=["magic", "totp"]))):
        return {"u": user["username"]}
    return a, ap


def _route_link(a, ap, name):
    c = TestClient(ap)
    tok = a.create_magic_token("login", user_id=a.store.get_user_by_name(name)["id"], payload={"next": "/r"})
    c.post(f"/auth/magic/{tok}", follow_redirects=False)
    return c


def _mit_totp(a, name):
    uid = a.create_user(name, password=PW, email=f"{name}@example.com")
    geheim = a.totp_begin(uid)["secret"]
    a.totp_confirm(uid, pyotp.TOTP(geheim).at(_zeit.time() - 30))
    return geheim


_JSON, _HTML10 = {"accept": "application/json"}, {"accept": "text/html"}
a10, ap10 = _route_app()
_g10 = _mit_totp(a10, "rt-totp")
c10 = _route_link(a10, ap10, "rt-totp")
_j10 = c10.get("/r", headers=_JSON)
_h10 = c10.get("/r", headers=_HTML10, follow_redirects=False)
r.check("G10 (classic): route [\"magic\"], account with TOTP — after the link 401, step totp",
        _j10.status_code == 401 and _j10.headers.get("x-tinysesam-factor") == "totp",
        f"HTTP {_j10.status_code} {_j10.headers.get('x-tinysesam-factor')}")
r.check("… in the browser the redirect to the TOTP step (classic)",
        _h10.status_code == 307 and _h10.headers["location"].startswith("/auth/totp?next=/r"),
        f"{_h10.status_code} {_h10.headers.get('location')}")
c10.post("/auth/totp", data={"code": pyotp.TOTP(_g10).now(), "next": "/r"}, follow_redirects=False)
r.check("… with the code the route opens (classic)", c10.get("/r", headers=_JSON).json() == {"u": "rt-totp"})
# Global chain [password, totp]: until 2026-09-27 the same route opened after link and TOTP — without the
# password that the global chain demands. Since "aligning" (PO decision 2026-09-27) a
# route chain only tightens: first the missing step of the global sign-in, the password.
a10g, ap10g = _route_app(login_chain=["password", "totp"])
_g10g = _mit_totp(a10g, "rt-totp")
c10g = _route_link(a10g, ap10g, "rt-totp")
_j10g = c10g.get("/r", headers=_JSON)
_h10g = c10g.get("/r", headers=_HTML10, follow_redirects=False)
r.check("G10 (global chain [password, totp]): route [\"magic\"] — after the link first the step of the "
        "global chain (password), not the route alone",
        _j10g.status_code == 401 and _j10g.headers.get("x-tinysesam-factor") == "password"
        and _h10g.status_code == 307 and _h10g.headers["location"].startswith("/auth/login?next=/r"),
        f"HTTP {_j10g.status_code} {_j10g.headers.get('x-tinysesam-factor')} {_h10g.headers.get('location')}")
_login(c10g, "rt-totp", PW)
_j10g2 = c10g.get("/r", headers=_JSON)
c10g.post("/auth/totp", data={"code": pyotp.TOTP(_g10g).now(), "next": "/r"}, follow_redirects=False)
r.check("… then TOTP, after that the route opens (global chain)",
        _j10g2.status_code == 401 and _j10g2.headers.get("x-tinysesam-factor") == "totp"
        and c10g.get("/r", headers=_JSON).json() == {"u": "rt-totp"},
        f"HTTP {_j10g2.status_code} {_j10g2.headers.get('x-tinysesam-factor')}")
a10p, ap10p = _route_app()
_u10p = a10p.create_user("rt-passkey", password=PW, email="rtp@example.com")
a10p.store.add_webauthn(_u10p, b"cred-g10", b"pub", 0, "[]", "Laptop")
_j10p = _route_link(a10p, ap10p, "rt-passkey").get("/r", headers=_JSON)
r.check("G10: route [\"magic\"], account with passkey only — 401, step passkey",
        _j10p.status_code == 401 and _j10p.headers.get("x-tinysesam-factor") == "passkey",
        f"HTTP {_j10p.status_code} {_j10p.headers.get('x-tinysesam-factor')}")
a10o, ap10o = _route_app()
a10o.create_user("rt-ohne", password=PW, email="rto@example.com")
r.check("G10: without a second factor the link still opens the route alone (C, not D)",
        _route_link(a10o, ap10o, "rt-ohne").get("/r", headers=_JSON).json() == {"u": "rt-ohne"})
# magiclink_require_second_factor=False switches off the rule of the sign-in link — not the global one:
# the classic policy demands a set-up TOTP anyway, and a route chain no longer falls below
# it since 2026-09-27. Measured on the account with passkey only (only the link rule demands it).
a10a, ap10a = _route_app(magiclink_require_second_factor=False)
_u10a = a10a.create_user("rt-aus", password=PW, email="rta@example.com")
a10a.store.add_webauthn(_u10a, b"cred-g10a", b"pub", 0, "[]", "Laptop")
r.check("G10: magiclink_require_second_factor=False applies here too — the link suffices for the route (account with passkey)",
        _route_link(a10a, ap10a, "rt-aus").get("/r", headers=_JSON).json() == {"u": "rt-aus"})
_mit_totp(a10a, "rt-aus-totp")
_j10a = _route_link(a10a, ap10a, "rt-aus-totp").get("/r", headers=_JSON)
r.check("… a set-up TOTP is demanded by the classic rule anyway (the route does not fall below it)",
        _j10a.status_code == 401 and _j10a.headers.get("x-tinysesam-factor") == "totp",
        f"HTTP {_j10a.status_code} {_j10a.headers.get('x-tinysesam-factor')}")
a10k, ap10k = _route_app()
_g10k = _mit_totp(a10k, "rt-kette")
c10k = _route_link(a10k, ap10k, "rt-kette")
_vor10k = c10k.get("/r2", headers=_JSON)
c10k.post("/auth/totp", data={"code": pyotp.TOTP(_g10k).now(), "next": "/r2"}, follow_redirects=False)
r.check("G10: route [\"magic\", \"totp\"] — exactly one TOTP step, then open (no double step)",
        _vor10k.status_code == 401 and _vor10k.headers.get("x-tinysesam-factor") == "totp"
        and c10k.get("/r2", headers=_JSON).json() == {"u": "rt-kette"},
        f"HTTP {_vor10k.status_code} {_vor10k.headers.get('x-tinysesam-factor')}")
# (Mutation probe, executed: switch off the call of `_link_braucht` in
#  `_enforce_route_chain` → the TOTP, passkey and chain cases turn red.)

# ── Aligning route chains (PO decision 2026-09-27): a route chain only tightens ──────────────────
# Until then `require(factors=[…])` only checked its own list (and after G10 the link). A half
# session to which the GLOBAL rule still owed a factor got through: `factors=["password"]`
# opened the route of an account with TOTP after the password, `["pin", "password"]` after PIN and
# password likewise, and under `login_chain=["password", "totp"]` the password alone sufficed.
def _kette_app(**cfg):
    a, ap = _app(pin_enabled=True, **cfg)

    @ap.get("/pw")
    def _pw(user=Depends(a.require(factors=["password"]))):
        return {"u": user["username"]}

    @ap.get("/pinpw")
    def _pinpw(user=Depends(a.require(factors=["pin", "password"]))):
        return {"u": user["username"]}
    return a, ap


a_k, ap_k = _kette_app()
_g_k = _mit_totp(a_k, "rk-totp")
a_k.set_pin(a_k.store.get_user_by_name("rk-totp")["id"], "4711")
c_k = TestClient(ap_k)
_login(c_k, "rk-totp", PW)                                           # half session: TOTP missing
_j_k = c_k.get("/pw", headers=_JSON)
_h_k = c_k.get("/pw", headers=_HTML10, follow_redirects=False)
# (Mutation probe: switch off the check for `mfa_ok` in `_enforce_route_chain` → 200 → red.)
r.check("Aligning: route [\"password\"], account with TOTP, password only — 401, step totp (not open)",
        _j_k.status_code == 401 and _j_k.headers.get("x-tinysesam-factor") == "totp"
        and _h_k.status_code == 307 and _h_k.headers["location"].startswith("/auth/totp?next=/pw"),
        f"HTTP {_j_k.status_code} {_j_k.headers.get('x-tinysesam-factor')} {_h_k.headers.get('location')}")
c_k.post("/auth/totp", data={"code": pyotp.TOTP(_g_k).now(), "next": "/pw"}, follow_redirects=False)
r.check("… after the TOTP the route opens", c_k.get("/pw", headers=_JSON).json() == {"u": "rk-totp"})
c_kp = TestClient(ap_k)
c_kp.post("/auth/pin", data={"username": "rk-totp", "pin": "4711"}, follow_redirects=False)
_login(c_kp, "rk-totp", PW)
_j_kp = c_kp.get("/pinpw", headers=_JSON)
r.check("… route [\"pin\", \"password\"] after PIN and password: TOTP first there too (the global rule)",
        _j_kp.status_code == 401 and _j_kp.headers.get("x-tinysesam-factor") == "totp",
        f"HTTP {_j_kp.status_code} {_j_kp.headers.get('x-tinysesam-factor')}")
a_ko, ap_ko = _kette_app()
a_ko.create_user("rk-ohne", password=PW)
c_ko = TestClient(ap_ko)
_login(c_ko, "rk-ohne", PW)
r.check("… without a second factor the session is full after the password — the route opens at once (control)",
        c_ko.get("/pw", headers=_JSON).json() == {"u": "rk-ohne"})
a_kc, ap_kc = _kette_app(login_chain=["password", "totp"])
a_kc.create_user("rk-kette", password=PW)
c_kc = TestClient(ap_kc)
_login(c_kc, "rk-kette", PW)
_j_kc = c_kc.get("/pw", headers=_JSON)
r.check("… login_chain [password, totp], account still without TOTP: route [\"password\"] sends to the setup, "
        "instead of opening after the password",
        _j_kc.status_code == 401 and _j_kc.headers.get("x-tinysesam-factor") == "totp",
        f"HTTP {_j_kc.status_code} {_j_kc.headers.get('x-tinysesam-factor')}")

# ── Attack on the third round: findings and their latches ────────────────────────────────
from fastapi import HTTPException as _HTTPEx  # noqa: E402
from tinysesam import config_check as _kp3  # noqa: E402
from tinysesam.oidc import OIDCClient as _OC3  # noqa: E402


class _LDAP3:
    def __init__(self, eintraege):
        self.e = eintraege

    def authenticate(self, username, password):
        z = self.e.get(username)
        return dict(z, username=username, groups=[]) if z and password == "x" else None


# S1 (high): SAML not trusted — a name that is the address of a local account does not bind it.
a_s1, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", login_identifier="email")
opfer_s1 = a_s1.create_user("bob@example.com", password=PW, email="bob@example.com", is_admin=True)
neu_s1 = a_s1._check_saml("bob@example.com", {"email": ["bob@example.com"]})
r.check("Attack R3/S1: SAML (not trusted) with the address of a local account as NameID does not take it over",
        neu_s1 is not None and neu_s1["id"] != opfer_s1 and neu_s1["username"].startswith("saml-")
        and not neu_s1["is_admin"] and a_s1.store.get_federated_kennung("saml", opfer_s1) is None,
        str(neu_s1))
a_s1._check_saml("BOB@EXAMPLE.COM", {"email": ["bob@example.com"]})
r.check("… not in another spelling either", a_s1.store.get_federated_kennung("saml", opfer_s1) is None)

# S3: without a stable identifier an address name is rejected — not a new account on every login.
a_s3, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", saml_attr_id="objectGUID")
_vorher_s3 = len(a_s3.store.list_users())
_e1 = a_s3._check_saml("anna@corp.example", {"email": ["anna@corp.example"]})
_e2 = a_s3._check_saml("anna@corp.example", {"email": ["anna@corp.example"]})
r.check("Attack R3/S3: SAML not trusted, address name without identifier → rejected, no account per login",
        _e1 is None and _e2 is None and len(a_s3.store.list_users()) == _vorher_s3)

# S2 (medium): LDAP not trusted, sign-in with an address (filter via mail).
a_s2, _ = _app(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False,
               login_identifier="both")
chefin_s2 = a_s2.create_user("chefin@example.com", password=PW, email="chefin@example.com")
a_s2.ldap = _LDAP3({"chefin@example.com": {"id": "uuid-mallory", "email": "chefin@example.com", "name": "M"}})
_n_s2 = a_s2.store.user_count()
neu_s2 = a_s2._check_ldap("chefin@example.com", "x")
# Until 2026-09-27 this created an account `ldap-…`; since the review round (p1-d) the sign-in rejects —
# the address locally belongs to one account, the entry led to another.
r.check("Attack R3/S2: LDAP not trusted — the typed address neither becomes the account name nor binds an account",
        neu_s2 is None and a_s2.store.user_count() == _n_s2
        and a_s2.store.get_federated_kennung("ldap", chefin_s2) is None, str(neu_s2))

# S4 (high, pre-existing): control characters in the account name.
a_s4, app_s4 = _app(allow_signup=True)
try:
    a_s4.create_user("chefin\x01", password=PW)
    _s4_create = False
except ConfigError:
    _s4_create = True
_s4_reg = TestClient(app_s4).post("/auth/register", data={"username": "chefin​", "password": PW + "xyz",
                                                         "next": "/"}, follow_redirects=False)
r.check("Attack R3/S4: no account with control/format characters in the name (create_user, registration)",
        _s4_create and _s4_reg.status_code == 400 and a_s4.store.get_user_by_name("chefin​") is None,
        f"create={_s4_create} reg={_s4_reg.status_code}")
a_s4.create_user("chefin", password=PW)
_alt_s4 = a_s4.store.create_user("chefin\x01", None, None, False, [], False)       # existing data past the latch
try:
    a_s4._forward_response_headers(a_s4.get_user(_alt_s4))
    _s4_fwd = False
except _HTTPEx as e:
    _s4_fwd = e.status_code == 403
r.check("… and such existing data gets no remote user (fail-closed instead of `chefin`)", _s4_fwd)
a_s4o, app_s4o = _oidc({"sub": "s4-sub", "preferred_username": "chefin\x01", "email": "c4@example.com",
                        "email_verified": True})
_oidc_login(app_s4o)
_s4o = [u["username"] for u in a_s4o.store.list_users()]
r.check("… an IdP name with control characters is discarded (the proven address applies here)",
        _s4o == ["c4@example.com"], str(_s4o))
a_s4s, app_s4s = _oidc({"sub": "\x01s4", "preferred_username": ""})
_s4s_antwort = _oidc_login(app_s4s)
_s4s = [u["username"] for u in a_s4s.store.list_users()]
r.check("… and a `sub` with control characters yields a hashed substitute name, no rejection",
        _s4s_antwort.status_code == 303 and len(_s4s) == 1 and _s4s[0].startswith("oidc-")
        and "\x01" not in _s4s[0], f"{_s4s_antwort.status_code} {_s4s}")

# F8-2: errors of the client are no no for the account.
import httpx as _httpx3  # noqa: E402


class _Antwort3:
    def __init__(self, code, body):
        self.status_code, self._b = code, body

    def json(self):
        return self._b


_post3 = _httpx3.post
_oc3 = _OC3.__new__(_OC3)
_oc3.client_id, _oc3.client_secret = "c", "s"
_oc3.meta = lambda: {"token_endpoint": "https://idp.example/token", "issuer": "https://idp.example"}
_erg3 = {}
try:
    for code, body in ((401, {"error": "invalid_client"}), (400, {"error": "unauthorized_client"}),
                       (400, {"error": "unsupported_grant_type"}), (401, {}), (503, {}),
                       (400, {}), (400, {"error": "invalid_request"}), (400, {"error": "invalid_grant"}),
                       (400, {"error": "access_denied"})):
        _httpx3.post = lambda *a, _c=code, _b=body, **k: _Antwort3(_c, _b)
        _erg3[(code, body.get("error", "-"))] = _oc3.refresh("rt", "sub")[0]
finally:
    _httpx3.post = _post3
_soll3 = {(401, "invalid_client"): "fehler", (400, "unauthorized_client"): "fehler",
          (400, "unsupported_grant_type"): "fehler", (401, "-"): "fehler", (503, "-"): "fehler",
          (400, "-"): "abgelehnt", (400, "invalid_request"): "abgelehnt",      # Dex: revoked token
          (400, "invalid_grant"): "abgelehnt", (400, "access_denied"): "abgelehnt"}
r.check("Attack R3/F8-2: client errors, 401 and 5xx → „fehler\"; every other 4xx (also Dex' invalid_request) → no",
        _erg3 == _soll3, str({k: v for k, v in _erg3.items() if _soll3.get(k) != v}))
# … and a row of a client that is no longer configured is discarded, not exchanged as a no.
a_f2, _, _ = _oidc_mit_refresh("f2-konto")
_uid_f2 = a_f2.store.get_user_by_name("f2-konto")["id"]
_h_f2 = a_f2.store._one("SELECT token_hash FROM session")["token_hash"]
a_f2.store.set_oidc_sitzung(_h_f2, "app-weg", "f2-konto", "rt-weg")
a_f2.oidc.refresh = lambda rt, sub: ("abgelehnt", {}, {"error": "invalid_grant"})     # the fallback said no
a_f2.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60 WHERE client='app-weg'")
a_f2._oidc_nachpruefen(a_f2.store._one("SELECT * FROM session"))
a_f2._oidc_ausgang.abwarten()
r.check("… a row of a removed client goes, the session stays, the account gets no no",
        a_f2.store._one("SELECT COUNT(*) AS n FROM oidc_sitzung WHERE client='app-weg'")["n"] == 0
        and a_f2.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 1
        and (a_f2.store.get_user(_uid_f2)["idp_bestaetigt_at"] or 0) > 0)

# 3c/M1: chain ["magic","totp"], account with passkey without TOTP — the mailbox does not set up a TOTP for itself.
a_m1, ap_m1 = _link_app(login_chain=["magic", "totp"])
u_m1 = a_m1.create_user("pk-kette", password=PW, email="pkk@example.com")
a_m1.store.add_webauthn(u_m1, b"cred-m1", b"pub", 0, "[]", "Laptop")
c_m1, _ = _link_login(a_m1, ap_m1, "pk-kette")
_setup_m1 = c_m1.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False)
r.check("Attack R3/M1: sign-in link only + account with passkey → no TOTP self-setup",
        _setup_m1.status_code != 200 and not a_m1.store.has_confirmed_totp(u_m1)
        and any(z["event"] == "mfa_enrollment_denied" for z in a_m1.store.recent_audit(20)),
        f"HTTP {_setup_m1.status_code}")
a_m2, ap_m2 = _link_app(login_chain=["magic", "totp"])
a_m2.create_user("frisch-kette", password=PW, email="fk@example.com")
c_m2, _ = _link_login(a_m2, ap_m2, "frisch-kette")
r.check("… an account without a second factor still may (the price of C)",
        c_m2.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False).status_code == 200)

# S5: The configuration check says what the runtime does.
_w_v = " ".join(_kp3.check_config(TinySesamConfig(db_path=":memory:", admin_identifiers=["chef@example.com"],
                                             ldap_enabled=True, ldap_url="ldaps://d.example", ldap_auto_create=True,
                                             ldap_email_trusted=True))[1])
_w_n = " ".join(_kp3.check_config(TinySesamConfig(db_path=":memory:", admin_identifiers=["chef@example.com"],
                                             ldap_enabled=True, ldap_url="ldaps://d.example", ldap_auto_create=True,
                                             ldap_email_trusted=False))[1])
r.check("Attack R3/S5: config check — trusted source: „becomes first admin\"; not trusted: „NEVER\"",
        "trusted source" in _w_v and "NEVER" not in _w_v and "NEVER" in _w_n, _w_v[:200])
# The same check in German (`lang="de"`): the old wording.
_w_vd = " ".join(_kp3.check_config(TinySesamConfig(db_path=":memory:", admin_identifiers=["chef@example.com"],
                                              ldap_enabled=True, ldap_url="ldaps://d.example", ldap_auto_create=True,
                                              ldap_email_trusted=True, lang="de"))[1])
_w_nd = " ".join(_kp3.check_config(TinySesamConfig(db_path=":memory:", admin_identifiers=["chef@example.com"],
                                              ldap_enabled=True, ldap_url="ldaps://d.example", ldap_auto_create=True,
                                              ldap_email_trusted=False, lang="de"))[1])
r.check("… and in German (lang=\"de\"): „vertraute Quelle\" vs. „NIE\"",
        "vertraute Quelle" in _w_vd and "NIE" not in _w_vd and "NIE" in _w_nd and "trusted source" not in _w_vd,
        _w_vd[:200])
# (Mutation probes are in the commit: ignore name_zuordnen → S1 red; remove rejection without identifier →
#  S3 red; remove LDAP substitute name → S2 red; remove name_ungueltig in create_user → S4 red; header latch
#  removed → "fail-closed" red; client errors as a no again → F8-2 red; remove `bekannt` → "removed
#  client" red; remove the passkey check in totp_enrollment_user → M1 red.)

# ── Counter-check of the fixes (third round): detours and regressions ──────────────────────
import logging as _log3  # noqa: E402

# V1: LDAP not trusted — a mail value WITHOUT "@" is just as unproven.
a_v1, _ = _app(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False)
chefin_v1 = a_v1.create_user("chefin", password=PW, is_admin=True)
a_v1.ldap = _LDAP3({"chefin": {"id": "uuid-mallory", "email": "chefin", "name": "M"}})
_n_v1 = a_v1.store.user_count()
neu_v1 = a_v1._check_ldap("chefin", "x")
# Until 2026-09-27 this created an account `ldap-…`; since the review round (p1-d) it rejects: the identifier
# `chefin` locally belongs to one account, the entry led to another.
r.check("Counter-check R3/V1: LDAP not trusted, input = own mail value without „@\" → no takeover",
        neu_v1 is None and a_v1.store.user_count() == _n_v1
        and a_v1.store.get_federated_kennung("ldap", chefin_v1) is None, str(neu_v1))
# V2: … and a UPN (bind identifier, not the mail value) stays the account name, even without an identifier.
a_v2, _ = _app(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False)
a_v2.ldap = _LDAP3({"bob@corp.example": {"id": "", "email": "b.mail@corp.example", "name": "Bob"}})
neu_v2 = a_v2._check_ldap("bob@corp.example", "x")
r.check("… a UPN that is not the mail value signs in as before the fix (no regression)",
        neu_v2 is not None and neu_v2["username"] == "bob@corp.example" and not neu_v2["email"], str(neu_v2))

# V3: forward auth blocks only what the cleaning really removes; start finding for existing data.
a_v3, _ = _app()
_zwnj = a_v3.store.create_user("علی‌رضا", None, None, False, [], False)
_c0 = a_v3.store.create_user("chefin\x01", None, None, False, [], False)
try:
    _kopf_v3 = a_v3._forward_response_headers(a_v3.get_user(_zwnj))
except _HTTPEx:
    _kopf_v3 = None
r.check("Counter-check R3/V3: an existing name with ZWNJ gets its remote user (does not collide)",
        _kopf_v3 is not None and "‌".encode("utf-8").decode("latin-1") in _kopf_v3["Remote-User"])
_fang_v3 = []
_h_v3 = _log3.Handler()
_h_v3.emit = lambda rec: _fang_v3.append(rec.getMessage())
_log3.getLogger("tinysesam.security").addHandler(_h_v3)
try:
    TinySesam(TinySesamConfig(db_path=a_v3.cfg.db_path, cookie_secure=False, base_url="http://testserver"))
finally:
    _log3.getLogger("tinysesam.security").removeHandler(_h_v3)
r.check("… and the startup names existing names with control/format characters",
        any("account name(s) with control or format characters" in m and str(_c0) in m for m in _fang_v3))
# The named route (since self-service) works: renamed, then the remote user is back.
_neu_v3 = a_v3.change_username(_c0, "chefin-neu")
r.check("… and the route it names (auth.change_username) cleans the name up",
        any("auth.change_username" in m for m in _fang_v3) and _neu_v3 == "chefin-neu"
        and a_v3._forward_response_headers(a_v3.get_user(_c0))["Remote-User"] == "chefin-neu")

# V4: SAML identifier with edge control characters hits no foreign binding.
a_v4, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", saml_email_trusted=True)
echt_v4 = a_v4._check_saml("chefin", {})
fremd_v4 = a_v4._check_saml("chefin ", {})
r.check("Counter-check R3/V4: NameID `chefin` + U+2028 does not end up in the account of the bound `chefin`",
        echt_v4 is not None and fremd_v4 is None, f"{echt_v4 and echt_v4['id']} / {fremd_v4}")

# V5: SAML not trusted, the name comes from the address attribute itself (even without "@").
a_v5, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", saml_attr_username="email")
chefin_v5 = a_v5.create_user("chefin", password=PW, is_admin=True)
neu_v5 = a_v5._check_saml("opaque-mallory", {"email": ["chefin"]})
r.check("Counter-check R3/V5: SAML name from the address attribute (`chefin`) does not bind the local account",
        neu_v5 is not None and neu_v5["id"] != chefin_v5 and neu_v5["username"].startswith("saml-")
        and a_v5.store.get_federated_kennung("saml", chefin_v5) is None, str(neu_v5))

# I2: client newly created at the provider (different client_id) — no no, the row goes.
a_i2, _, _ = _oidc_mit_refresh("i2-konto")
_uid_i2 = a_i2.store.get_user_by_name("i2-konto")["id"]
a_i2.store._exec("UPDATE oidc_sitzung SET client_id='alte-client-id', geprueft_at = geprueft_at - 16 * 60")
a_i2.oidc.refresh = lambda rt, sub: ("abgelehnt", {}, {"error": "invalid_grant"})
a_i2._oidc_nachpruefen(a_i2.store._one("SELECT * FROM session"))
a_i2._oidc_ausgang.abwarten()
r.check("Counter-check R3/I2: token of an old client_id → row discarded, session stays, no no",
        a_i2.store._one("SELECT COUNT(*) AS n FROM oidc_sitzung")["n"] == 0
        and a_i2.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 1
        and (a_i2.store.get_user(_uid_i2)["idp_bestaetigt_at"] or 0) > 0)

# I3 + I4: a passkey account sets up TOTP only with a passkey in the session or in the operator window.
a_i3, ap_i3 = _link_app(login_chain=["password", "totp"])
u_i3 = a_i3.create_user("pk-reset", password=PW, email="pkr@example.com")
a_i3.store.add_webauthn(u_i3, b"cred-i3", b"pub", 0, "[]", "Laptop")
c_i3 = TestClient(ap_i3)
c_i3.post("/auth/login", data={"username": "pk-reset", "password": PW, "next": "/"}, follow_redirects=False)
r.check("Counter-check R3/I3: passkey account, only password in the session (e.g. after „forgot password\") → no setup",
        c_i3.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False).status_code != 200)
_h_i3 = a_i3.store._one("SELECT token_hash FROM session")["token_hash"]
a_i3.store.set_session_factors(_h_i3, ["password", "passkey"], mfa_ok=False)
r.check("… with the passkey in the same session the owner may",
        c_i3.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False).status_code == 200)
a_i4, ap_i4 = _link_app(login_chain=["magic", "totp"])
u_i4 = a_i4.create_user("pk-verloren", password=PW, email="pkv@example.com")
a_i4.store.add_webauthn(u_i4, b"cred-i4", b"pub", 0, "[]", "Altes Handy")
a_i4.grant_mfa_enrollment(u_i4, 60)
c_i4, _ = _link_login(a_i4, ap_i4, "pk-verloren")
r.check("Counter-check R3/I4: a window opened by the operator wins (lost device, link only)",
        c_i4.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False).status_code == 200)

# I5: if the session gets a new token during the exchange, the rotated refresh token is not lost.
a_i5, _, _ = _oidc_mit_refresh("i5-konto")
_alt_i5 = a_i5.store._one("SELECT token_hash FROM session")["token_hash"]


def _tausch_mit_rotation(rt, sub):
    # In the middle of the exchange: step-up or similar gives the session a new token, the OIDC row follows.
    a_i5.store._exec("UPDATE session SET token_hash='neu-i5' WHERE token_hash=?", (_alt_i5,))
    a_i5.store._exec("UPDATE oidc_sitzung SET token_hash='neu-i5' WHERE token_hash=?", (_alt_i5,))
    return "ok", {"sub": sub}, {"refresh_token": "rt-rotiert"}


a_i5.oidc.refresh = _tausch_mit_rotation
a_i5.store._exec("PRAGMA foreign_keys=OFF")
a_i5.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a_i5._oidc_nachpruefen(a_i5.store._one("SELECT * FROM session"))
a_i5._oidc_ausgang.abwarten()
_z_i5 = a_i5.store._one("SELECT refresh FROM oidc_sitzung WHERE token_hash='neu-i5'")
r.check("Counter-check R3/I5: rotation during the exchange — the new refresh token lands on the row",
        _z_i5 is not None and a_i5.store.tresor.decrypt(_z_i5["refresh"]) == "rt-rotiert")
# (Mutation probes: LDAP back on "@" instead of the mail value → V1 red, V2 red; forward latch back to
#  name_ungueltig → V3 red; start finding removed → V3b red; trim the identifier → V4 red; client_id comparison
#  removed → I2 red; "not magic" instead of "passkey" → I3 red; window check removed → I4 red;
#  alt_verschluesselt removed → I5 red.)

# ── Upper limit without successful re-check (PO decision 2026-09-25: 25 hours) ───────────────
a_ob, _, c_ob = _oidc_mit_refresh("ob-konto")
_uid_ob = a_ob.store.get_user_by_name("ob-konto")["id"]
r.check("Upper limit: default 25 hours, state of the row set at login",
        a_ob.cfg.oidc_session_max_unverified_hours == 25
        and a_ob.store._one("SELECT erfolg_at FROM oidc_sitzung")["erfolg_at"] is not None)
a_ob.oidc.refresh = lambda rt, sub: ("ok", {"sub": sub}, {})
_vor_ob = int(_zeit.time()) - 2 * 3600
a_ob.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60, erfolg_at = ?", (_vor_ob,))
c_ob.get("/auth/me")
a_ob._oidc_ausgang.abwarten()
r.check("… a yes at the exchange resets the state",
        (a_ob.store._one("SELECT erfolg_at FROM oidc_sitzung")["erfolg_at"] or 0) > _vor_ob)
a_ob.oidc.refresh = lambda rt, sub: ("fehler", {}, {"error": "invalid_client"})
a_ob.store._exec("UPDATE oidc_sitzung SET erfolg_at = ?", (int(_zeit.time()) - 24 * 3600,))
r.check("… 24 hours without a yes: the session stays", c_ob.get("/auth/me").status_code == 200)
a_ob.store._exec("UPDATE oidc_sitzung SET erfolg_at = ?", (int(_zeit.time()) - 26 * 3600,))
_antw_ob = c_ob.get("/auth/me").status_code
r.check("… 26 hours without a yes: the session ends, with an audit row — and that is NOT a no for the keys",
        _antw_ob == 401 and a_ob.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0
        and a_ob.store._one("SELECT 1 FROM audit WHERE event='oidc_unconfirmed'") is not None
        and (a_ob.store.get_user(_uid_ob)["idp_bestaetigt_at"] or 0) > 0, f"HTTP {_antw_ob}")
a_ob0, _, c_ob0 = _oidc_mit_refresh("ob-aus", oidc_session_max_unverified_hours=0)
a_ob0.store._exec("UPDATE oidc_sitzung SET erfolg_at = 1000")
r.check("… oidc_session_max_unverified_hours=0 switches the limit off", c_ob0.get("/auth/me").status_code == 200)
# (Mutation probes: remove the check in `_oidc_nachpruefen` → "26 hours" red; `erfolg=True`
#  at the exchange removed → "a yes resets the state" red; `_idp_nein` instead of just deleting → keys check
#  red.)

# ── Schema 11, intermediate state: `fehlserie` without column `art` is recreated (R2-3) ────────
_pfad_z = str(Path(tempfile.mkdtemp()) / "zwischen.db")
Store(_pfad_z).db.close()
_roh = sqlite3.connect(_pfad_z)
_roh.execute("DROP TABLE fehlserie")
_roh.execute("CREATE TABLE fehlserie (topf TEXT PRIMARY KEY, anzahl INTEGER NOT NULL, "
             "seit INTEGER NOT NULL, zuletzt INTEGER NOT NULL)")
_roh.commit()
_roh.close()
_z = Store(_pfad_z)
_spalten = {z["name"] for z in _z._all("PRAGMA table_info(fehlserie)")}
r.check("Intermediate state: a `fehlserie` without `art` is recreated instead of breaking every sign-in",
        "art" in _spalten and _z.fehlserie_erhoehen("x", "password") == 1, str(_spalten))
_z.db.close()

# ── Schema 11: a file from 0.20.x gets the table at startup ───────────────────────────────
_pfad = str(Path(tempfile.mkdtemp()) / "alt.db")
Store(_pfad).db.close()
_roh = sqlite3.connect(_pfad)
_roh.execute("DROP TABLE fehlserie")
_roh.execute("PRAGMA user_version = 10")
_roh.commit()
_roh.close()
_neu = Store(_pfad)
_tabellen = {z["name"] for z in _neu._all("SELECT name FROM sqlite_master WHERE type='table'")}
r.check("Schema 10 → today: `fehlserie` is created at startup, the stamp follows",
        "fehlserie" in _tabellen
        and int(_neu.db.execute("PRAGMA user_version").fetchone()[0]) == Store.SCHEMA_VERSION >= 11)
_neu.db.close()
os.remove(_pfad)

sys.exit(r.done())
