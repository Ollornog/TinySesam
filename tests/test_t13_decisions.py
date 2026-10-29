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
_WRONG = _itertools.count()   # always NEW wrong passwords: a repetition counts only once since 0.24.9

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.store import Store  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("T-13 decisions (B2-4, B2-6, B2-8, F-27, H-3, H-5)")
IDP = "https://idp.example.invalid"


def _app(**cfg):
    reason = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, base_url="http://testserver", lang="de")
    reason.update(cfg)
    auth = TinySesam(TinySesamConfig(**reason))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# ── B2-4: minimum length depending on the factor situation ────────────────────────────────
FOURTEEN, FIFTEEN, ELEVEN = "Kiefer-Spur-47", "Kiefer-Spur-478", "Kiefer-Spur"
auth, app = _app()
r.check("B2-4: default (no chain, the password signs in alone): 14 characters too short",
        "min. 15" in (auth.password_policy_error(FOURTEEN) or ""), str(auth.password_policy_error(FOURTEEN)))
r.check("… 15 characters pass", auth.password_policy_error(FIFTEEN) is None,
        str(auth.password_policy_error(FIFTEEN)))
with TestClient(_app(allow_signup=True)[1]) as c:
    response = c.post("/auth/register", data={"username": "newcomer", "password": FOURTEEN})
r.check("… and registration adheres to it", response.status_code == 400 and "min. 15" in response.text,
        f"HTTP {response.status_code}")
# A chain with a second factor protects the password only if nobody may set it up themselves:
# with `mfa_enrollment="first_login"` (default) whoever knows only the initial password binds their own
# authenticator at the first login — the password then signs in alone (attack on B2-4).
for chain, enroll, expected in ((["password", "totp"], "first_login", "min. 15"),
                                      (["password", "totp"], "grace", "min. 15"),
                                      (["password", "totp"], "strict", None),
                                      (["pin", "password"], "strict", None),
                                      (["password"], "strict", "min. 15")):
    a_k, _ = _app(login_chain=chain, pin_enabled="pin" in chain, mfa_enrollment=enroll)
    finding = a_k.password_policy_error(ELEVEN)
    r.check(f"B2-4: chain {chain}, enrollment {enroll}: 11 characters "
            f"{'pass' if expected is None else 'too short'}",
            (finding is None) if expected is None else (expected in (finding or "")), str(finding))
auth.set_security("password_min_length_single_factor", 8)
r.check("B2-4 configurable: set to 8, the base length applies again",
        auth.password_policy_error(ELEVEN) is None, str(auth.password_policy_error(ELEVEN)))
try:
    auth.set_security("password_min_length_single_factor", 7)
    _under = False
except ConfigError:
    _under = True
r.check("… but never below 8 (the limit of the password rule)", _under)
# (Mutation probe: always return `base` in `_password_min_length` → the first three red;
#  `_password_alone_possible` always True → the two chains with a second factor red.)

# ── B2-6: failed attempts in a row, without time window ──────────────────────────────────
auth, app = _app()
for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
             ("account_max_consecutive_failures", 10)):
    auth.set_security(k, v)
PW = "Series-Password-2026"
uid = auth.create_user("series", password=PW, email="series@example.com")
c = TestClient(app)


def _login(client, name, pw):
    return client.post("/auth/login", data={"username": name, "password": pw}, follow_redirects=False)


for _ in range(10):
    _login(c, "series", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
locked = _login(c, "series", PW)
r.check("B2-6: after 10 failed attempts in a row the sign-in locks — even with the correct password",
        locked.status_code == 429 and "in Folge" in locked.text, f"HTTP {locked.status_code}")
r.check("… the lock appears exactly once in the audit log",
        sum(1 for z in auth.store.recent_audit(200) if z["event"] == "lockout_series") == 1)
for _ in range(10):
    _login(c, "does-not-exist", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
foreign = _login(c, "does-not-exist", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
r.check("… an unknown name gets the same response (no oracle for existing accounts)",
        foreign.status_code == 429 and "in Folge" in foreign.text, f"HTTP {foreign.status_code}")

# Aged, otherwise this would test only the 90 days and not the limit (as measured: the mutation
# "gc also clears triggered ones" stayed green as long as the series was fresh).
auth.store._exec("UPDATE failure_series SET last_seen = last_seen - 91 * 86400 WHERE folded='series'")
auth.gc()
r.check("B2-6: gc() does not clear a triggered series, not even after 90 days (it does not expire)",
        auth.store.failure_series("series") == 10, str(auth.store.failure_series("series")))
auth.store.increase_failure_series("old-and-half")
auth.store._exec("UPDATE failure_series SET last_seen = last_seen - 91 * 86400 WHERE folded='old-and-half'")
auth.gc()
r.check("… but it does clear one that was not triggered after 90 days of quiet", auth.store.failure_series("old-and-half") == 0)

auth.lift_lockout(uid, methods=("password",))           # the path of the self-service reset
r.check("B2-6: a reset ends the series (rebind)", _login(c, "series", PW).status_code == 303,
        "still locked after the reset")

uid2 = auth.create_user("change", password=PW)
for _ in range(9):
    _login(TestClient(app), "change", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
_login(TestClient(app), "change", PW)                        # successful access
for _ in range(9):
    _login(TestClient(app), "change", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
r.check("B2-6: a successful access resets the series (9 + success + 9 does not lock)",
        _login(TestClient(app), "change", PW).status_code == 303, str(auth.store.failure_series("change")))

auth._record_login("change", "198.51.100.1", False, "password_change")
r.check("B2-6: a miss that is not a sign-in (password change) does not count",
        auth.store.failure_series("change") == 0, str(auth.store.failure_series("change")))

for _ in range(10):
    _login(TestClient(app), "change", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
admin_id = auth.create_user("boss", password=PW, is_admin=True)
ca = TestClient(app)
_login(ca, "boss", PW)
new = ca.post(f"/auth/admin/api/users/{uid2}/password", json={"password": "Whole-New-Password-1x"})
r.check("B2-6: the password reset in the panel ends the series",
        new.status_code == 200 and _login(TestClient(app), "change", "Whole-New-Password-1x").status_code == 303,
        f"HTTP {new.status_code}, series {auth.store.failure_series('change')}")

for _ in range(10):
    _login(TestClient(app), "change", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
from tinysesam.__main__ import main as _cli  # noqa: E402
# The CLI ends via `sys.exit` — uncaught that ended this test with exit 0, in the middle of the run
# and green (a skip is not a green).
_code = 0
with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
    try:
        _cli(["unlock", "--db", auth.cfg.db_path, "change"])
    except SystemExit as e:
        _code = e.code or 0
r.check("B2-6: `tinysesam unlock` ends the series", _code == 0 and auth.store.failure_series("change") == 0,
        f"exit {_code}, series {auth.store.failure_series('change')}")

for value, applies in ((9, False), (10, True), (100000, True), (100001, False)):
    try:
        auth.set_security("account_max_consecutive_failures", value)
        ok_ = True
    except ConfigError:
        ok_ = False
    r.check(f"B2-6 configurable: {value} {'allowed' if applies else 'rejected'}", ok_ is applies)
# (Mutation probes: delete the series check in `begin_attempt` → first check red;
#  delete `delete_failure_series` in `lift_lockout` → reset/panel red; delete the condition
#  `anzahl < ?` in `gc_failure_series` → "does not expire" red.)

# Findings from the attack on B2-6 — each one its own test.
auth, app = _app()
for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
             ("account_max_consecutive_failures", 10)):
    auth.set_security(k, v)
uid_a = auth.create_user("atom", password=PW)
for _ in range(9):
    auth._record_login("atom", "198.51.100.2", False, "password",
                       attempt=auth._begin_attempt("atom", "198.51.100.2", "password"))
unclosed = [auth._begin_attempt("atom", f"198.51.100.{10 + i}", "password") for i in range(5)]
r.check("B2-6 atomic: at the limit exactly ONE running attempt gets through, not every one",
        sum(1 for v in unclosed if v is not None) == 1, str(unclosed))
auth._record_login("atom", "198.51.100.10", True, "password", attempt=next(v for v in unclosed if v))
r.check("… and a correct attempt takes back its pre-booking, but does not clear the series",
        auth.store.failure_series("atom") == 9, str(auth.store.failure_series("atom")))
v = auth._begin_attempt("atom", "198.51.100.3", "password")
auth._revert_attempt(v)
r.check("B2-6: a withdrawn attempt (directory outage) does not count",
        auth.store.failure_series("atom") == 9, str(auth.store.failure_series("atom")))

uid_t = auth.create_user("second", password=PW)
for _ in range(10):
    auth._record_login("second", "198.51.100.4", False, "totp",
                       attempt=auth._begin_attempt("second", "198.51.100.4", "totp"))
auth.lift_lockout(uid_t, methods=("password",))            # self-service reset
r.check("B2-6 + R4-13: the self-service reset does NOT clear TOTP misses of the series",
        auth.store.failure_series("second") == 10 and auth._begin_attempt("second", "198.51.100.5", "password") is None,
        str(auth.store.failure_series("second")))
# Conversely the FIRST factors: anyone can send wrong PINs, even without knowing a secret.
# If they stayed after the reset, the reset the message recommends would no longer help (R2-2).
uid_pin = auth.create_user("pinopfer", password=PW)
for _ in range(10):
    auth._record_login("pinopfer", "198.51.100.8", False, "pin",
                       attempt=auth._begin_attempt("pinopfer", "198.51.100.8", "pin"))
auth.lift_lockout(uid_pin, methods=("password",))          # self-service reset
r.check("B2-6: the reset clears a series of wrong PINs (first factor, producible by anyone)",
        auth.store.failure_series("pinopfer") == 0, str(auth.store.failure_series("pinopfer")))

manager_t = auth.create_user("boss-t", password=PW, is_admin=True)
cpt = TestClient(app)
cpt.post("/auth/login", data={"username": "boss-t", "password": PW}, follow_redirects=False)
new_t = cpt.post(f"/auth/admin/api/users/{uid_t}/password", json={"password": "From-Operator-Set-1xxxx"})
r.check("… the operator clears it entirely (password reset in the panel, also the TOTP part)",
        new_t.status_code == 200 and auth.store.failure_series("second") == 0, str(auth.store.failure_series("second")))
# And via the path the routes take: a non-login attempt pre-books nothing.
v_pc = auth._begin_attempt("second", "198.51.100.6", "password_change")
auth._record_login("second", "198.51.100.6", False, "password_change", attempt=v_pc)
r.check("B2-6: a miss at the password change (via begin_attempt) books no series",
        auth.store.failure_series("second") == 0, str(auth.store.failure_series("second")))

# ── B2-6 × directory: the series under the name in the directory (G5, G5-N1) ───────────────────
# The series counts under the TYPED identifier. After a rename in the directory (locally
# `alice`, bound via entryUUID, there `alice.neu`) the person types `alice.neu`. Until 2026-09-26
# no way back cleared the series under it: own typos added up over the years, a
# stranger could lock them out permanently with enough failed attempts, and `tinysesam unlock alice.neu` aborted
# with "No account".
class _Directory:
    """Dummy of the LDAP client after the bind: the entry for the typed identifier (with a
    filter over `uid` AND `mail` also for the address)."""

    def __init__(self, entries):
        self.entries = entries

    def authenticate(self, username, password):
        e = self.entries.get(username)
        if not e or e["pw"] != password:
            return None
        return {"username": username, "email": e.get("email"), "name": username, "groups": [],
                "id": e.get("id"), "email_verified": None}


LPW = "Directory-Pw1xx"
auth_v, app_v = _app(ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
                     ldap_auto_create=True, passkey_enabled=False)
for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
             ("account_max_consecutive_failures", 10)):
    auth_v.set_security(k, v)
auth_v.ldap = _Directory({"alice": {"pw": LPW, "id": "uuid-alice"}})
_first_v = _login(TestClient(app_v), "alice", LPW)
uid_v = auth_v.store.get_user_by_name("alice")["id"]


def _binding_name(uid):
    z = auth_v.store._one("SELECT directory_name_folded FROM federated_identity WHERE user_id=?", (uid,))
    return z["directory_name_folded"] if z else "(no Binding)"


_first_name = _binding_name(uid_v)
auth_v.ldap = _Directory({"alice.new": {"pw": LPW, "id": "uuid-alice"}})     # renamed in the directory
for _ in range(3):
    _login(TestClient(app_v), "alice.new", f"wrong-wrong-1-xx{next(_WRONG)}")
_three_v = auth_v.store.failure_series("alice.new")
_full_v = _login(TestClient(app_v), "alice.new", LPW)
# (Mutation probe: omit the name from the binding in `Store.count_identifiers` → 3 → red.)
r.check("G5: after the rename in the directory the full sign-in ends the series under the "
        "new name (and clears its window)",
        _first_v.status_code == 303 and _three_v == 3 and _full_v.status_code == 303
        and auth_v.store.failure_series("alice.new") == 0 and auth_v.store.count_fails(0, username="alice.new") == 0,
        f"HTTP {_first_v.status_code}/{_full_v.status_code}, series {_three_v} → {auth_v.store.failure_series('alice.new')}")
r.check("… the same account; the directory name is on the binding — only because it is not the account's own",
        auth_v.store.get_user(uid_v)["username"] == "alice" and _first_name is None
        and _binding_name(uid_v) == "alice.new", f"{_first_name!r} → {_binding_name(uid_v)!r}")

for _ in range(10):
    _login(TestClient(app_v), "alice.new", f"wrong-wrong-1-xx{next(_WRONG)}")
_locked_v = _login(TestClient(app_v), "alice.new", LPW)
auth_v._end_series(uid_v)
# (Mutation probe: only name and address again in `_end_series` → red.)
r.check("G5: at the limit (429 even with the correct password) the operator path "
        "(`_end_series`) clears the series under the directory name",
        _locked_v.status_code == 429 and auth_v.store.failure_series("alice.new") == 0
        and _login(TestClient(app_v), "alice.new", LPW).status_code == 303,
        f"HTTP {_locked_v.status_code}, series {auth_v.store.failure_series('alice.new')}")
for _ in range(10):
    _login(TestClient(app_v), "alice.new", f"wrong-wrong-1-xx{next(_WRONG)}")
auth_v.create_user("boss-v", password=PW, is_admin=True)
_cv = TestClient(app_v)
_login(_cv, "boss-v", PW)
_panel_v = _cv.post(f"/auth/admin/api/users/{uid_v}/password", json={"password": "Operator-Pw-15x"})
r.check("… likewise the password reset in the panel", _panel_v.status_code == 200
        and auth_v.store.failure_series("alice.new") == 0, f"HTTP {_panel_v.status_code}, {auth_v.store.failure_series('alice.new')}")


def _unlock(identifier):
    from_, fail, code = io.StringIO(), io.StringIO(), 0
    with redirect_stdout(from_), redirect_stderr(fail):
        try:
            _cli(["unlock", "--db", auth_v.cfg.db_path, identifier])
        except SystemExit as e:
            code = e.code or 0
    return code, from_.getvalue() + fail.getvalue()


for _ in range(10):
    _login(TestClient(app_v), "alice.new", f"wrong-wrong-1-xx{next(_WRONG)}")
_login(TestClient(app_v), "alice", f"wrong-wrong-1-xx{next(_WRONG)}")          # the old name: gone from the directory
_code_v, _text_v = _unlock("alice.new")
# (Mutation probe: delete `account_with_binding_name` → the account is not found, the series
#  under `alice` stays → red.)
r.check("G5: `tinysesam unlock alice.new` — the name as typed — finds the account and ends "
        "its series under all identifiers",
        _code_v == 0 and "Lockout for 'alice.new' lifted" in _text_v
        and auth_v.store.failure_series("alice.new") == 0 and auth_v.store.failure_series("alice") == 0,
        f"exit {_code_v}, {_text_v!r}, series {auth_v.store.failure_series('alice.new')}/{auth_v.store.failure_series('alice')}")
# Existing data: the series is already full, but the directory name was never noted (it only arises with the
# next SUCCESSFUL sign-in — and that is locked).
auth_v.store._exec("UPDATE federated_identity SET directory_name_folded = NULL")
for _ in range(10):
    _login(TestClient(app_v), "alice.new", f"wrong-wrong-1-xx{next(_WRONG)}")
_code_b, _text_b = _unlock("alice.new")
# (Mutation probe: rebuild the abort "No account" before the clearing → red.)
r.check("… also in existing data without a note: no account, but the counters under the identifier are cleared (rc 0)",
        _code_b == 0 and "No account" in _text_b and auth_v.store.failure_series("alice.new") == 0
        and _login(TestClient(app_v), "alice.new", LPW).status_code == 303,
        f"exit {_code_b}, {_text_b!r}, series {auth_v.store.failure_series('alice.new')}")
_code_n, _text_n = _unlock("gives-es-nowhere")
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

_manager_w = auth_v.create_user("boss", password=PW, email="boss@example.com")
auth_v.ldap = _Directory({"boss@example.com": {"pw": LPW, "id": "uuid-third", "email": "boss@example.com"}})
for _ in range(4):
    _login(TestClient(app_v), "boss@example.com", f"wrong-wrong-1-xx{next(_WRONG)}")
_before_w = (auth_v.store.count_fails(0, username="boss@example.com"), auth_v.store.failure_series("boss@example.com"))
_accounts_w = auth_v.store.user_count()
_buffer_w = io.StringIO()
_check_w = _log_g5.StreamHandler(_buffer_w)
_sec_g5.seclog.addHandler(_check_w)
try:
    _third = _login(TestClient(app_v), "boss@example.com", LPW)
finally:
    _sec_g5.seclog.removeHandler(_check_w)
_rejected_w = [dict(z) for z in auth_v.store._all("SELECT * FROM audit WHERE event='ldap_identifier_rejected'")]
# (Mutation probe: switch off the check against `only_account` in `_resolve_foreign_identity` → the
#  third party gets 303 and an account → red.)
r.check("p1-d (C): the sign-in of a directory third party under the address of a local account is "
        "rejected and booked as a failed attempt — without account, without binding",
        _before_w == (4, 4) and _third.status_code == 401
        and auth_v.store.get_federated_user("ldap", "uuid-third") is None
        and auth_v.store.user_count() == _accounts_w
        and auth_v.store.count_fails(0, username="boss@example.com") == 5
        and auth_v.store.failure_series("boss@example.com") == 5,
        f"before {_before_w}, HTTP {_third.status_code}, "
        f"{auth_v.store.count_fails(0, username='boss@example.com')}/{auth_v.store.failure_series('boss@example.com')}")
r.check("… with reason in the audit log (identifier_of_two_accounts, both accounts) and remedy in the security log",
        len(_rejected_w) == 1
        and _rejected_w[0]["detail"] == f"reason=identifier_of_two_accounts local={_manager_w} directory=new"
        and "tinysesam rename" in _buffer_w.getvalue(), f"{_rejected_w} {_buffer_w.getvalue()[:200]!r}")
_holder = _login(TestClient(app_v), "boss@example.com", PW)
# Until 2026-09-27 this counter-check held on to the defect: the 4 failed attempts also applied to the
# third party's LDAP password, and the owner cleared them. Now only her own secret opens a session under her
# address — her sign-in clears what can only be directed against her.
r.check("… the owner clears both with her sign-in — under her address only her secret still applies",
        _holder.status_code == 303 and auth_v.store.count_fails(0, username="boss@example.com") == 0
        and auth_v.store.failure_series("boss@example.com") == 0,
        f"HTTP {_holder.status_code}, {auth_v.store.count_fails(0, username='boss@example.com')}")


# ── Review round locks/counters (2026-09-27): one identifier, one account ──────────────────────
def _ldap_app():
    a, ap = _app(ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
                 ldap_auto_create=True, passkey_enabled=False)
    for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
                 ("account_max_consecutive_failures", 10)):
        a.set_security(k, v)
    return a, ap


def _session_from(a, response):
    tok = response.cookies.get(a.session_cookie_name)
    z = a.store._one("SELECT user_id FROM session WHERE token_hash=?", (a.store.session_hash(tok),)) if tok else None
    return z["user_id"] if z else None


MPW = "Mallory-Pw-15xy"
# p1-d (C), existing data: Mallory is already called `alice.neu` locally BEFORE Alice is renamed so in the directory.
# Under `alice.neu` the route then checked Mallory's password AND Alice's LDAP password; with every
# sign-in of her own Mallory cleared window and series — 120 failed attempts from one IP, no lock,
# after which Alice's correct password opened HER session. Now it opens nothing under `alice.neu`.
a_d, ap_d = _ldap_app()
a_d.ldap = _Directory({"alice": {"pw": LPW, "id": "uuid-alice"}})
_login(TestClient(ap_d), "alice", LPW)
_alice_d = a_d.store.get_user_by_name("alice")["id"]
_mallory_d = a_d.create_user("alice.new", password=MPW)
a_d.ldap = _Directory({"alice.new": {"pw": LPW, "id": "uuid-alice"}})
for _ in range(10):
    for _ in range(4):
        _login(TestClient(ap_d, client=("203.0.113.66", 1)), "alice.new", f"wrong-wrong-1-xx{next(_WRONG)}")
    _login(TestClient(ap_d, client=("203.0.113.66", 1)), "alice.new", MPW)
_ev_d0 = [e["event"] for e in a_d.own_events(_mallory_d, 1000)]
_login(TestClient(ap_d, client=("203.0.113.66", 1)), "alice.new", f"wrong-wrong-1-xx{next(_WRONG)}")
_ev_d1 = [e["event"] for e in a_d.own_events(_mallory_d, 1000)]
_hit_d = _login(TestClient(ap_d, client=("203.0.113.66", 1)), "alice.new", LPW)
_ev_d2 = [e["event"] for e in a_d.own_events(_mallory_d, 1000)]
# (Mutation probe: switch off the check against `only_account` → 303, session of Alice → red.)
r.check("p1-d (C): a local account under the directory name of another person — their correct "
        "LDAP password opens no session under this identifier, guessing there is worthless",
        _hit_d.status_code == 401 and _session_from(a_d, _hit_d) is None
        and a_d.store.get_federated_user("ldap", "uuid-alice") == _alice_d
        and a_d.store._one("SELECT directory_name_folded FROM federated_identity WHERE user_id=?", (_alice_d,))["directory_name_folded"] is None,
        f"HTTP {_hit_d.status_code}, session {_session_from(a_d, _hit_d)}")
# The rejection arises only if the LDAP password was right — on Mallory's account page it would be the
# oracle. (Mutation probe: take `ldap_identifier_rejected` out of `_OWN_VIEW` → red.)
r.check("… and Mallory's account page sees a hit like a miss (no oracle about the rejection)",
        len(_ev_d1) - len(_ev_d0) == len(_ev_d2) - len(_ev_d1) == 1 and _ev_d1[0] == _ev_d2[0]
        and bool(a_d.store._one("SELECT 1 AS x FROM audit WHERE event='ldap_identifier_rejected'")),
        f"{_ev_d0[:2]} {_ev_d1[:2]} {_ev_d2[:2]}")
# Read path with OLD rows (an older version after a rollback wrote them): the rejection under its up-to-0.24.x
# name stays just as hidden, and the old name `login_lokal` is shown in the English spelling.
a_d.store.audit_log("ldap_kennung_abgewiesen", "alice.new", "203.0.113.66", "grund=kennung_zweier_konten")
a_d.store.audit_log("login_lokal", "alice.new", "203.0.113.66", "password")
_ev_d3 = [e["event"] for e in a_d.own_events(_mallory_d, 1000)]
r.check("… old rows: `ldap_kennung_abgewiesen` stays hidden on the account page, `login_lokal` appears as `login_local`",
        len(_ev_d3) - len(_ev_d2) == 1 and _ev_d3[0] == "login_local"
        and "ldap_kennung_abgewiesen" not in _ev_d3 and "ldap_identifier_rejected" not in _ev_d3,
        f"{_ev_d2[:2]} {_ev_d3[:3]}")
r.check("… Mallory's own sign-in continues to work (counter-check)",
        _login(TestClient(ap_d), "alice.new", MPW).status_code == 303)
a_d.change_username(_mallory_d, "mallory", by_operator=True)
_afterwards_d = _login(TestClient(ap_d), "alice.new", LPW)
r.check("… after the rename by the operator (the remedy from the log line) Alice signs in under "
        "`alice.new`", _afterwards_d.status_code == 303 and _session_from(a_d, _afterwards_d) == _alice_d,
        f"HTTP {_afterwards_d.status_code}")

# p1-d (A): Once Alice has signed in under `alice.neu`, the name is on her binding — and no
# other account can take it: self-service, registration, admin, CLI, the database itself.
a_a, ap_a = _ldap_app()
a_a.ldap = _Directory({"alice": {"pw": LPW, "id": "uuid-alice"}})
_login(TestClient(ap_a), "alice", LPW)
_alice_a = a_a.store.get_user_by_name("alice")["id"]
a_a.ldap = _Directory({"alice.new": {"pw": LPW, "id": "uuid-alice"}})
_login(TestClient(ap_a), "alice.new", LPW)
_mallory_a = a_a.create_user("mallory", password=MPW)
_grant_a = a_a.identifier_taken("ALICE.NEW")
try:
    a_a.change_username(_mallory_a, "alice.new", by_operator=True)    # not even the operator
    _itself_a = "renamed"
except ValueError:
    _itself_a = "rejected"
try:
    a_a.store.set_username(_mallory_a, "Alice.New")
    _raw_a = "written"
except sqlite3.IntegrityError:
    _raw_a = "IntegrityError"
try:
    a_a.store.create_user("alice.new")
    _setup_a = "angelegt"
except sqlite3.IntegrityError:
    _setup_a = "IntegrityError"
# Registration no longer exists alongside LDAP (PO decision 2026-09-27) — the setup fails.
try:
    _app(ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
         passkey_enabled=False, allow_signup=True)
    _reg_a = "built"
except ConfigError as _e_reg:
    _reg_a = str(_e_reg)
_cli_from_a = io.StringIO()
with redirect_stdout(_cli_from_a), redirect_stderr(_cli_from_a):
    try:
        _cli(["rename", "--db", a_a.cfg.db_path, "mallory", "alice.new"])
        _cli_a = 0
    except SystemExit as e:
        _cli_a = e.code
# (Mutation probes: take `account_with_directory_name` out of `identifier_taken` → the pre-check red;
#  take the federated part out of the identifier triggers → "Datenbank" red.)
r.check("p1-d (A): the directory name of another account counts as taken (pre-check, any spelling)",
        _grant_a is not None and _grant_a["id"] == _alice_a, str(_grant_a))
r.check("… and the database rejects it — rename and create (identifier trigger)",
        _raw_a == "IntegrityError" and _setup_a == "IntegrityError", f"{_raw_a} {_setup_a}")
r.check("… renaming (also by the operator) and `tinysesam rename` refuse, registering does not "
        "exist alongside LDAP at all",
        _itself_a == "rejected" and "allow_signup" in _reg_a and "ldap_enabled" in _reg_a and _cli_a == 1
        and "name in the directory" in _cli_from_a.getvalue()
        and a_a.store.get_user(_mallory_a)["username"] == "mallory",
        f"{_itself_a}, registration {_reg_a}, CLI rc {_cli_a} {_cli_from_a.getvalue()[:120]!r}")
# Alongside LDAP nobody renames themselves, not even to a free name (PO decision
# 2026-09-27): otherwise a local account could take the directory name of a person who has
# never signed in, and lock them out. (Mutation probe: switch off the check in `change_username`
# → red; the flag of the account page → red.)
try:
    a_a.change_username(_mallory_a, "mallory2")
    _ldap_itself = "renamed"
except ValueError as _e_sb:
    _ldap_itself = str(_e_sb)
_c_sb = TestClient(ap_a)
_login(_c_sb, "mallory", MPW)
_page_html_sb = _c_sb.get("/auth/account", headers={"accept": "text/html"}).text
_route_sb = _c_sb.post("/auth/account/username", json={"username": "mallory3"})
r.check("Alongside LDAP: no self-rename (method, route, account page)",
        _ldap_itself == a_a.t("api.username_from_directory") and _route_sb.status_code in (400, 403)
        and "data-act=setname" not in _page_html_sb and a_a.store.get_user(_mallory_a)["username"] == "mallory",
        f"{_ldap_itself!r} HTTP {_route_sb.status_code}")
a_a.change_username(_alice_a, "alice.new", by_operator=True)
r.check("… Alice's account may take it (her own binding does not count)",
        a_a.store.get_user(_alice_a)["username"] == "alice.new")

# p1-b: The operator renames an LDAP account whose name is the directory name (G13). Until then
# the binding held NULL (the name was its own, after all), and after the rename `alice` dropped out of
# `count_identifiers` and out of the identifier space: if a stranger filled the series under it, neither the
# panel reset nor a full sign-in by another route helped (429 until `tinysesam unlock alice`), and another
# account could call itself `alice`.
a_b, ap_b = _ldap_app()
a_b.ldap = _Directory({"alice": {"pw": LPW, "id": "uuid-alice"}})
_login(TestClient(ap_b), "alice", LPW)
_alice_b = a_b.store.get_user_by_name("alice")["id"]
a_b.create_user("boss-b", password=PW, is_admin=True)
a_b.change_username(_alice_b, "alice.meier", by_operator=True)
_identifiers_b = a_b.store.count_identifiers(_alice_b)
for _i in range(10):
    _login(TestClient(ap_b, client=(f"203.0.113.{_i + 10}", 1)), "alice", f"wrong-wrong-1-xx{next(_WRONG)}")
_prior_b = _login(TestClient(ap_b), "alice", LPW).status_code
_c_b = TestClient(ap_b)
_login(_c_b, "boss-b", PW)
_panel_b = _c_b.post(f"/auth/admin/api/users/{_alice_b}/password", json={"password": "Operator-Pw-15x"}).status_code
_after_b = _login(TestClient(ap_b), "alice", LPW)
_mallory_b = a_b.create_user("mallory", password=MPW)
# (Mutation probe: omit `_remember_directory_name` in `_set_identifier` → series stays, 429, and
#  `mallory` may call itself `alice` → red.)
r.check("p1-b: after the rename by the operator the old name counts as directory name — the "
        "panel reset clears the series under it, the LDAP sign-in works again",
        _identifiers_b == {"alice", "alice.meier"} and _prior_b == 429 and _panel_b == 200
        and _after_b.status_code == 303 and _session_from(a_b, _after_b) == _alice_b,
        f"{_identifiers_b}, {_prior_b}/{_panel_b}/{_after_b.status_code}")
r.check("… and no other account can call itself that",
        a_b.identifier_taken("alice", exclude_id=_mallory_b) is not None)

# p1-a: After a rename and reassignment in the directory the previous owner kept the name on
# its binding. Every full sign-in of the previous owner (and every operator reset for it) ended
# the series under which guessing against the NEW owner took place, and `tinysesam unlock x` named the
# account with the younger binding and cleared its own series too.
a_x, ap_x = _ldap_app()
a_x.ldap = _Directory({"x": {"pw": LPW, "id": "uuid-a"}, "berta": {"pw": LPW, "id": "uuid-b"}})
_login(TestClient(ap_x), "berta", LPW)
_berta_x = a_x.store.get_user_by_name("berta")["id"]
a_x.store._exec("UPDATE federated_identity SET bound_at = bound_at - 100 WHERE user_id=?", (_berta_x,))
_login(TestClient(ap_x), "x", LPW)
_anton_x = a_x.store.get_user_by_name("x")["id"]
a_x.change_username(_anton_x, "anton", by_operator=True)
a_x.set_password(_anton_x, PW)
a_x.ldap = _Directory({"x.alt": {"pw": LPW, "id": "uuid-a"}, "x": {"pw": LPW, "id": "uuid-b"}})
_login(TestClient(ap_x), "x", LPW)                  # Berta is now called `x` in the directory


def _binding_name_x(uid):
    return a_x.store._one("SELECT directory_name_folded FROM federated_identity WHERE user_id=?", (uid,))["directory_name_folded"]


_names_x = (_binding_name_x(_anton_x), _binding_name_x(_berta_x))
for _i in range(9):
    _login(TestClient(ap_x, client=(f"203.0.113.{_i + 10}", 1)), "x", f"wrong-wrong-1-xx{next(_WRONG)}")
_login(TestClient(ap_x), "anton", PW)                # full sign-in of the previous owner
a_x._end_series(_anton_x)                         # operator reset for him
# (Mutation probe: omit the deletion on foreign bindings in `set_binding_name` → Anton's
#  binding keeps `x` → red.)
r.check("p1-a: the most recent sign-in under `x` proves who owns the name — the previous owner loses it, "
        "his sign-in and his reset leave the series of the new owner standing",
        _names_x == (None, "x") and a_x.store.count_identifiers(_anton_x) == {"anton"}
        and a_x.store.failure_series("x") == 9, f"{_names_x}, {a_x.store.count_identifiers(_anton_x)}, {a_x.store.failure_series('x')}")
_login(TestClient(ap_x, client=("203.0.113.99", 1)), "x", f"wrong-wrong-1-xx{next(_WRONG)}")
for _i in range(3):
    _login(TestClient(ap_x, client=(f"203.0.113.{_i + 50}", 1)), "anton", f"wrong-wrong-1-xx{next(_WRONG)}")
_from_x = io.StringIO()
with redirect_stdout(_from_x), redirect_stderr(_from_x):
    try:
        _cli(["unlock", "--db", a_x.cfg.db_path, "x"])
    except SystemExit:
        pass    # the CLI ends with sys.exit; what is measured is the output and the database
_unlock_x = [dict(z) for z in a_x.store._all("SELECT username, detail FROM audit WHERE event='unlock_cli'")]
r.check("… `tinysesam unlock x` names the new owner and leaves the previous owner's own series standing",
        [z["username"] for z in _unlock_x] == ["berta"] and a_x.store.failure_series("x") == 0
        and a_x.store.failure_series("anton") == 3, f"{_unlock_x}, anton {a_x.store.failure_series('anton')}")
# Existing data: both still carry the name (written before this version). Then it counts for neither, and
# `unlock` names no account (which one signed in most recently like this is recorded nowhere).
a_x.store._exec("UPDATE federated_identity SET directory_name_folded='x' WHERE user_id=?", (_anton_x,))
for _i in range(3):
    _login(TestClient(ap_x, client=(f"203.0.113.{_i + 70}", 1)), "x", f"wrong-wrong-1-xx{next(_WRONG)}")
_login(TestClient(ap_x), "anton", PW)
_series_x2 = a_x.store.failure_series("x")
_from_x2 = io.StringIO()
with redirect_stdout(_from_x2), redirect_stderr(_from_x2):
    try:
        _cli(["unlock", "--db", a_x.cfg.db_path, "x"])
    except SystemExit:
        pass    # the CLI ends with sys.exit; what is measured is the output and the database
# (Mutation probes: omit the second safeguard in `count_identifiers` → Anton's sign-in clears the
#  series → red; `account_with_binding_name` by `bound_at` again → names anton → red.)
r.check("… in existing data with two carriers: the name counts for neither, `unlock` names none and clears only under `x`",
        _series_x2 == 3 and a_x.store.failure_series("x") == 0
        and "x" not in a_x.store.count_identifiers(_anton_x) and "x" not in a_x.store.count_identifiers(_berta_x)
        and "No account 'x'" in _from_x2.getvalue(), f"series {_series_x2}, {_from_x2.getvalue()!r}")

# A stale note does not stop a new person: if someone ELSE is now called `y` in the directory
# (reassignment), their first sign-in creates the account `y` — the note on the previous owner is
# stale and is deleted. (Mutation probe: omit `release_directory_name` in `check_ldap` →
# the creation fails as "taken", 401 → red.)
a_y, ap_y = _ldap_app()
a_y.ldap = _Directory({"y": {"pw": LPW, "id": "uuid-a"}})
_login(TestClient(ap_y), "y", LPW)
_old_y = a_y.store.get_user_by_name("y")["id"]
a_y.change_username(_old_y, "yves", by_operator=True)           # notes `y` (p1-b)
_note_y = a_y.store._one("SELECT directory_name_folded FROM federated_identity WHERE user_id=?", (_old_y,))["directory_name_folded"]
a_y.ldap = _Directory({"y.alt": {"pw": LPW, "id": "uuid-a"}, "y": {"pw": LPW, "id": "uuid-c"}})
_new_y = _login(TestClient(ap_y), "y", LPW)
_account_y = a_y.store.get_user_by_name("y")
r.check("p1-a: a new directory entry under a noted name creates its account; the note "
        "on the previous owner is dropped",
        _note_y == "y" and _new_y.status_code == 303 and _account_y is not None
        and _session_from(a_y, _new_y) == _account_y["id"] != _old_y
        and a_y.store._one("SELECT directory_name_folded FROM federated_identity WHERE user_id=?", (_old_y,))["directory_name_folded"] is None,
        f"note {_note_y!r}, HTTP {_new_y.status_code}")

# p1-d (C), address: filter over uid AND mail, `ldap_email_trusted=False` (default) — LDAP accounts
# carry no address locally. A local account carries Alice's directory address (in the finding via
# registration, which has not existed alongside LDAP since 2026-09-27; here created by the operator or
# from existing data); until 2026-09-27 its own sign-in under the address cleared the counters against
# Alice's LDAP password, without any rename.
a_m, ap_m = _ldap_app()
_alice_entry = {"pw": LPW, "id": "uuid-alice", "email": "alice@corp.example"}
a_m.ldap = _Directory({"alice": _alice_entry, "alice@corp.example": _alice_entry})
_login(TestClient(ap_m), "alice", LPW)
_alice_m = a_m.store.get_user_by_name("alice")["id"]
_reg_m = a_m.create_user("mallory", password=MPW, email="alice@corp.example")
for _ in range(10):
    for _ in range(4):
        _login(TestClient(ap_m, client=("203.0.113.66", 1)), "alice@corp.example", f"wrong-wrong-1-xx{next(_WRONG)}")
    _login(TestClient(ap_m, client=("203.0.113.66", 1)), "alice@corp.example", MPW)
_hit_m = _login(TestClient(ap_m, client=("203.0.113.66", 1)), "alice@corp.example", LPW)
# (Mutation probe: switch off the check against `only_account` → 303, session of Alice → red.)
r.check("p1-d (C): a local account with the directory address of another person — their LDAP password "
        "opens no session under the address",
        bool(_reg_m) and _hit_m.status_code == 401 and _session_from(a_m, _hit_m) is None,
        f"registration {_reg_m}, HTTP {_hit_m.status_code}")
r.check("… under her name Alice continues to sign in (counter-check)",
        _session_from(a_m, _login(TestClient(ap_m), "alice", LPW)) == _alice_m)

# ── B2-8: PIN as first factor — explicitly allowed, with its own limit ──────────────────
auth, app = _app(pin_enabled=True)


@app.get("/general")
def _general(user=Depends(auth.require())):
    return {"ok": True}


@app.get("/detail")
def _detail(user=Depends(auth.require(factors=["pin", "password"]))):
    return {"ok": True}


pin_uid = auth.create_user("pinnutzer", password=PW)
auth.set_pin(pin_uid, "4711")
cp = TestClient(app)
page_html = cp.get("/auth/login")
r.check("B2-8: the login page offers the PIN as first factor (pin_login, default)",
        "/auth/pin" in page_html.text, "no PIN route on the login page")
cp.post("/auth/pin", data={"username": "pinnutzer", "pin": "4711"}, follow_redirects=False)
r.check("… with the PIN alone one reaches the general page",
        cp.get("/general", follow_redirects=False).status_code == 200)
r.check("… the detail page demands more (chain pin → password per route)",
        cp.get("/detail", follow_redirects=False).status_code != 200)
_login(cp, "pinnutzer", PW)
r.check("… and opens after the password", cp.get("/detail", follow_redirects=False).status_code == 200)
a_from, _ = _app(pin_enabled=True, pin_login=False)
r.check("B2-8 configurable: pin_login=False takes the PIN off the login page",
        "/auth/pin" not in TestClient(_).get("/auth/login").text)
row = list(auth.all_security())
r.check("B2-8: the PIN attempts are in the panel with the lock settings",
        row.index("pin_max_attempts") == row.index("account_max_consecutive_failures") + 1
        and row.index("account_max_consecutive_failures") == row.index("account_attempt_factor") + 1,
        str(row[:8]))
for _ in range(auth._sec("pin_max_attempts")):
    TestClient(app).post("/auth/pin", data={"username": "pinnutzer", "pin": "0000"})
locked = TestClient(app).post("/auth/pin", data={"username": "pinnutzer", "pin": "4711"})
r.check("B2-8: after pin_max_attempts misses the PIN path is closed", locked.status_code == 429,
        f"HTTP {locked.status_code}")
r.check("… and the PIN misses count into the series (B2-6)", auth.store.failure_series("pinnutzer") >= 5)


# ── OIDC helpers: network-free, real callback ─────────────────────────────────────────────
class _Claims(dict):
    def validate(self, *a, **k):
        pass


def _oidc(claims, **cfg):
    auth, app = _app(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe",
                     oidc_client_secret="secret", **cfg)
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize",
                       "token_endpoint": IDP + "/token", "userinfo_endpoint": IDP + "/userinfo",
                       "jwks_uri": IDP + "/jwks"}
    _set(auth, claims)
    from tinysesam.oidc import OIDCClient
    auth.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
    return auth, app


def _set(auth, claims):
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})


def _oidc_login(app):
    c = TestClient(app, raise_server_exceptions=False)
    start = c.get("/auth/oidc/start", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)


# ── F-27: email collision with a local account ───────────────────────────────────────────
a27, app27 = _oidc({"sub": "k-1", "preferred_username": "new", "email": "local@example.com",
                    "email_verified": True})
local = a27.create_user("local", password=PW, email="local@example.com")
response = _oidc_login(app27)
r.check("F-27: proven address of a local account → 409, no 500", response.status_code == 409,
        f"HTTP {response.status_code}")
r.check("… no second account, no link, a line for the operator",
        a27.store.get_user_by_name("new") is None and not a27.store.get_oidc_user(IDP, "k-1")
        and any(z["event"] == "oidc_ident_taken" for z in a27.store.recent_audit(50)))
a27b, app27b = _oidc({"sub": "k-2", "preferred_username": "new2", "email": "local@example.com",
                      "email_verified": False})
local_b = a27b.create_user("local", password=PW, email="local@example.com")
response = _oidc_login(app27b)
new2 = a27b.store.get_user_by_name("new2")
r.check("F-27 + H-3: an UNPROVEN foreign address does not collide and takes nothing over",
        response.status_code == 303 and new2 is not None and not new2["email"]
        and a27b.store.get_user(local_b)["email"] == "local@example.com",
        f"HTTP {response.status_code}")

# ── H-3: an address without proof is not used ────────────────────────────────────────────
a3, app3 = _oidc({"sub": "h3-1", "email": "foreign@example.com", "email_verified": False})
_oidc_login(app3)
accounts = [dict(u) for u in a3.store.list_users()]
k3 = accounts[0] if accounts else None
r.check("H-3: without proof no name from the address, no address in the account, no Remote-Email",
        k3 is not None and k3["username"].startswith("oidc-") and not k3["email"]
        and not a3._forward_response_headers(k3).get("Remote-Email"), str(k3))
a3b, app3b = _oidc({"sub": "h3-2", "email": "taken@example.com", "email_verified": True})
_oidc_login(app3b)
k3b = a3b.store.get_user_by_name("taken@example.com")
r.check("… with proof it is used (name, account, Remote-Email)",
        k3b is not None and k3b["email"] == "taken@example.com" and k3b["email_verified"]
        and a3b._forward_response_headers(k3b).get("Remote-Email") == "taken@example.com")
a3c, app3c = _oidc({"sub": "h3-3", "email": "entra@example.com"}, oidc_email_verified_default=True)
_oidc_login(app3c)
r.check("… a provider without a claim counts only with the operator's explicit statement",
        a3c.store.get_user_by_name("entra@example.com") is not None)
a3d, app3d = _oidc({"sub": "h3-4", "email": "no@example.com", "email_verified": False},
                   oidc_email_verified_default=True)
_oidc_login(app3d)
r.check("… an explicit false stays false, even with this statement",
        all(not u["email"] for u in a3d.store.list_users()))
a3e, app3e = _oidc({"sub": "h3-5", "preferred_username": "late", "email": "late@example.com"})
_oidc_login(app3e)
_set(a3e, {"sub": "h3-5", "preferred_username": "late", "email": "late@example.com",
             "email_verified": True})
_oidc_login(app3e)
r.check("H-3: if the provider supplies the proof later, the address enters the account as proven",
        a3e.store.get_user_by_name("late")["email"] == "late@example.com"
        and a3e.store.get_user_by_name("late")["email_verified"])
a3f, app3f = _oidc({"sub": "h3-6", "preferred_username": "late2", "email": "taken@example.com"})
_oidc_login(app3f)
a3f.create_user("holder", password=PW, email="taken@example.com")
_set(a3f, {"sub": "h3-6", "preferred_username": "late2", "email": "taken@example.com",
             "email_verified": True})
_oidc_login(app3f)
r.check("… unless it now belongs to another account (then it stays without)",
        not a3f.store.get_user_by_name("late2")["email"]
        and any(z["event"] == "oidc_email_taken" for z in a3f.store.recent_audit(50)))
for wish, proven, expected in (("victim@example.com", False, "oidc-"), ("victim@example.com", True, "victim@example.com"),
                                 ("victim\uff20example.com", False, "oidc-"), ("victim\ufe6bexample.com", False, "oidc-"),
                                 ("other@example.com", True, "victim@example.com"), ("klarname", False, "klarname")):
    a3g, app3g = _oidc({"sub": f"h3-pu-{wish}-{proven}", "preferred_username": wish,
                        "email": "victim@example.com", "email_verified": proven})
    _oidc_login(app3g)
    names = [u["username"] for u in a3g.store.list_users()]
    r.check(f"H-3: preferred_username={wish!r} with {'proven' if proven else 'unproven'} address → {expected}…",
            len(names) == 1 and names[0].startswith(expected), str(names))
# (Mutation probes: `proven_mail = mail` in oidc.py → the first H-3 check red; delete the check for
#  `@` in `preferred_username` → the cases with an address as name red.)

# ── H-5: the IdP takes back what it has given ────────────────────────────────────────────
MAP = {"admins": "__admin__", "editors": "editor"}
a5, app5 = _oidc({"sub": "h5-1", "preferred_username": "idpchef", "groups": ["admins", "editors"]},
                 oidc_group_role_map=MAP)
_oidc_login(app5)
boss = a5.store.get_user_by_name("idpchef")
r.check("H-5: admin group at the IdP → admin flag, noted as “from the IdP” (2)", boss["is_admin"] == 2,
        str(boss["is_admin"]))
_set(a5, {"sub": "h5-1", "preferred_username": "idpchef", "groups": ["editors"]})
_oidc_login(app5)
boss = a5.store.get_user_by_name("idpchef")
r.check("… if the IdP no longer delivers the group, the flag is gone at the next login",
        not boss["is_admin"] and "editor" in a5.user_roles(boss), str(dict(boss)))
r.check("… with a line in the audit log", any(z["event"] == "idp_admin_revoke" for z in a5.store.recent_audit(50)))
hand = a5.create_user("handadmin", password=PW, is_admin=True)
a5.apply_idp_groups(hand, [], MAP)
r.check("H-5: an admin flag granted by hand is never taken by the IdP", a5.store.get_user(hand)["is_admin"] == 1)
idp_admin = a5.create_user("idpzwei", password=PW)
a5.apply_idp_groups(idp_admin, ["admins"], MAP)
a5.apply_idp_groups(idp_admin, [], {"editors": "editor"})
r.check("… and a mapping without an admin target revokes nothing (it manages no admin right)",
        a5.store.get_user(idp_admin)["is_admin"] == 2)
a5.apply_idp_groups(idp_admin, ["cn=admins,ou=g,dc=x"], {"cn=admins": "__admin__"}, dn=True)
a5.apply_idp_groups(idp_admin, ["cn=other,ou=g,dc=x"], {"cn=admins": "__admin__"}, dn=True)
r.check("H-5 also applies to LDAP DNs (the same path)", not a5.store.get_user(idp_admin)["is_admin"])
# Finding from the attack on H-5: the panel sends the admin checkbox with every save of the roles
# — `set_admin(True)` silently turned the 2 into a 1, and the revocation never worked again.
a5p, app5p = _oidc({"sub": "h5-p", "preferred_username": "panelfall", "groups": ["admins"]},
                   oidc_group_role_map=MAP)
_oidc_login(app5p)
_pf = a5p.store.get_user_by_name("panelfall")
a5p.create_user("boss", password=PW, is_admin=True)
cpan = TestClient(app5p)
cpan.post("/auth/login", data={"username": "boss", "password": PW}, follow_redirects=False)
stored = cpan.post(f"/auth/admin/api/users/{_pf['id']}/roles", json={"roles": ["editor"], "is_admin": True})
r.check("H-5: saving roles in the panel leaves an IdP admin flag as it is (2)",
        stored.status_code == 200 and a5p.store.get_user(_pf["id"])["is_admin"] == 2,
        f"HTTP {stored.status_code}, is_admin={a5p.store.get_user(_pf['id'])['is_admin']}")
_set(a5p, {"sub": "h5-p", "preferred_username": "panelfall", "groups": []})
_oidc_login(app5p)
r.check("… and the next login without admin group takes it", not a5p.store.get_user(_pf["id"])["is_admin"])
_normal = a5p.create_user("regular", password=PW)
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
_ITEMS6 = ["chef6@example.com", "deputy6@example.com"]
a6, app6 = _oidc({**_C6, "groups": ["admins"]}, oidc_group_role_map=MAP, admin_identifiers=_ITEMS6)
_oidc_login(app6)
_boss6 = a6.store.get_user_by_name("chef6")
r.check("G6: admin group at the IdP → admin from the IdP (2), no owner", (_boss6["is_admin"], _boss6["is_owner"]) == (2, 0),
        str(dict(_boss6)))
_vice6 = a6.create_user("deputy6", password=PW, email="deputy6@example.com")
_set(a6, {**_C6, "groups": []})
_err6 = io.StringIO()
with redirect_stderr(_err6):
    _oidc_login(app6)
_boss6 = a6.store.get_user_by_name("chef6")
_audit6 = [(z["event"], z["username"], z["detail"]) for z in a6.store.recent_audit(50)]
r.check("G6: the IdP takes the last admin — the allowlist does NOT promote again in the same login",
        (_boss6["is_admin"], _boss6["is_owner"]) == (0, 0), str(dict(_boss6)))
r.check("… with line admin_bootstrap_denied after_idp_withdrawal, without admin_bootstrap",
        ("admin_bootstrap_denied", "chef6", "after_idp_withdrawal") in _audit6
        and not any(e == "admin_bootstrap" for e, _, _ in _audit6), str(_audit6[:6]))
# stderr is a buffer here, not a console (as in the container) — the token therefore goes to
# `<db_path>.claim` (T-17), not to stderr; `tests/test_operations_findings.py` (b) measures both paths.
_file6 = a6.cfg.db_path + ".claim"
_tok6 = Path(_file6).read_text(encoding="utf-8").strip() if os.path.exists(_file6) else ""
r.check("… and the one-time token goes to the operator immediately (not only at the next start) — "
        "without a console into <db_path>.claim, not onto stderr",
        bool(_tok6) and _tok6 == a6.admin_claim_token() and _tok6 not in _err6.getvalue(),
        f"{_file6} {bool(_tok6)} {_err6.getvalue()[-200:]}")
with redirect_stderr(io.StringIO()):
    _oidc_login(app6)
r.check("… the next login does not promote either", not a6.store.get_user_by_name("chef6")["is_admin"])
with redirect_stderr(io.StringIO()):
    _login(TestClient(app6), "deputy6", PW)
r.check("… and no other allowlist account (the marker applies to the instance)",
        (a6.store.get_user(_vice6)["is_admin"], a6.store.get_user(_vice6)["is_owner"]) == (0, 0)
        and any(z["event"] == "admin_bootstrap_denied" and z["username"] == "deputy6"
                for z in a6.store.recent_audit(20)), str(dict(a6.store.get_user(_vice6))))
_boss6 = a6.store.get_user_by_name("chef6")
r.check("G6: the emergency path remains — the one-time token makes admin and owner",
        a6._consume_admin_claim(a6.admin_claim_token(), _boss6)
        and (a6.store.get_user(_boss6["id"])["is_admin"], a6.store.get_user(_boss6["id"])["is_owner"]) == (1, 1))
# Counter-checks: the marker arises only if really no admin remains, and disturbs neither the
# fresh instance nor the path from demo into operation (there purge_demo deletes the last admin).
a6h, app6h = _oidc({**_C6, "sub": "g6-h", "groups": ["admins"]}, oidc_group_role_map=MAP,
                   admin_identifiers=_ITEMS6)
_oidc_login(app6h)
a6h.create_user("handchef6", password=PW, is_admin=True)
_set(a6h, {**_C6, "sub": "g6-h", "groups": []})
_oidc_login(app6h)
r.check("G6: if the IdP revokes an admin while an admin by hand remains, no marker arises",
        not a6h.store.get_user_by_name("chef6")["is_admin"]
        and a6h.store.get_setting("allowlist_after_idp_revocation") is None)
a6f, app6f = _app(admin_identifiers=_ITEMS6)
_f6 = a6f.create_user("deputy6", password=PW, email="deputy6@example.com")
_login(TestClient(app6f), "deputy6", PW)
r.check("G6: fresh instance — the first allowlist login becomes admin and owner",
        (a6f.store.get_user(_f6)["is_admin"], a6f.store.get_user(_f6)["is_owner"]) == (1, 1))
_db6d = str(Path(tempfile.mkdtemp()) / "t.db")
with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
    TinySesam(TinySesamConfig(db_path=_db6d, cookie_secure=False, demo_mode=True))
    a6d, app6d = _app(db_path=_db6d, admin_identifiers=_ITEMS6)
_d6 = a6d.create_user("deputy6", password=PW, email="deputy6@example.com")
_login(TestClient(app6d), "deputy6", PW)
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


@app_i.get("/inside")
def _inside(user=Depends(auth_i.require())):
    return {"ok": True}


r.check("F-05: default 8 h inactivity without “Stay signed in”, with it: off",
        auth_i.store.idle_sec == (8 * 3600, 0), str(auth_i.store.idle_sec))
auth_i.create_user("quiet", password=PW)
ci = TestClient(app_i)
ci.post("/auth/login", data={"username": "quiet", "password": PW}, follow_redirects=False)   # without remember
r.check("… freshly signed in one gets in", ci.get("/inside", follow_redirects=False).status_code == 200)
auth_i.store._exec("UPDATE session SET last_seen = last_seen - 8 * 3600 - 5")
r.check("… after 8 h without a request the session is gone (not just rejected, deleted)",
        ci.get("/inside", follow_redirects=False).status_code != 200
        and auth_i.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0)
ci2 = TestClient(app_i)
ci2.post("/auth/login", data={"username": "quiet", "password": PW, "remember": "1"}, follow_redirects=False)
auth_i.store._exec("UPDATE session SET last_seen = last_seen - 30 * 86400")
r.check("… with “Stay signed in” only the absolute lifetime counts (default)",
        ci2.get("/inside", follow_redirects=False).status_code == 200)
auth_j, app_j = _app(session_idle_minutes_remember=60)


@app_j.get("/inside")
def _inside_j(user=Depends(auth_j.require())):
    return {"ok": True}


auth_j.create_user("quiet", password=PW)
cj = TestClient(app_j)
cj.post("/auth/login", data={"username": "quiet", "password": PW, "remember": "1"}, follow_redirects=False)
cj.get("/inside")
_before = auth_j.store._one("SELECT last_seen FROM session")["last_seen"]
cj.get("/inside")
r.check("F-05: a second request in the same minute does not write (no lock per request)",
        auth_j.store._one("SELECT last_seen FROM session")["last_seen"] == _before)
auth_j.store._exec("UPDATE session SET last_seen = last_seen - 61 * 60")
r.check("F-05 configurable: also for “Stay signed in” (here 60 min)",
        cj.get("/inside", follow_redirects=False).status_code != 200)
auth_j.create_user("aktiv", password=PW)
ck = TestClient(app_j)
ck.post("/auth/login", data={"username": "aktiv", "password": PW, "remember": "1"}, follow_redirects=False)
auth_j.store._exec("UPDATE session SET last_seen = last_seen - 50 * 60, created_at = created_at - 50 * 60 "
                   "WHERE user_id = (SELECT id FROM users WHERE username='active')")
ck.get("/inside")                                              # activity resets the clock
auth_j.store._exec("UPDATE session SET last_seen = last_seen - 50 * 60 "
                   "WHERE user_id = (SELECT id FROM users WHERE username='active')")
r.check("F-05: whoever is active stays in (50 + 50 min, but never 60 in one stretch)",
        ck.get("/inside", follow_redirects=False).status_code == 200)
# (Mutation probes: delete the idle check in `get_session` → "after 8 h … gone" red; delete the
#  write-back of `zuletzt` → "whoever is active stays in" red.)

# The choice survives the completion of a chain: password (with checkbox) → TOTP creates a NEW full
# session (privilege change, new token); `_successor` carries the choice over. Without it every
# "Stay signed in" session with a second factor would silently fall back to the 8-h limit.
import time as _clock_k  # noqa: E402

import pyotp as _pyotp  # noqa: E402
auth_k, app_k = _app(login_chain=["password", "totp"])


@app_k.get("/inside")
def _inside_k(user=Depends(auth_k.require())):
    return {"ok": True}


uid_k = auth_k.create_user("twofold", password=PW)
_secret_text_k = auth_k.totp_begin(uid_k)["secret"]
auth_k.totp_confirm(uid_k, _pyotp.TOTP(_secret_text_k).at(_clock_k.time() - 30))
ckk = TestClient(app_k)
ckk.post("/auth/login", data={"username": "twofold", "password": PW, "remember": "1"}, follow_redirects=False)
_half_k = auth_k.store._one("SELECT token_hash, stay_chosen FROM session")
ckk.post("/auth/totp", data={"code": _pyotp.TOTP(_secret_text_k).now(), "next": "/"}, follow_redirects=False)
_full_k = auth_k.store._all("SELECT token_hash, stay_chosen, mfa_ok FROM session")
r.check("F-05: “Stay signed in” survives the second factor (new full session carries the choice)",
        _half_k["stay_chosen"] == 1 and len(_full_k) == 1
        and _full_k[0]["token_hash"] != _half_k["token_hash"] and _full_k[0]["stay_chosen"] == 1,
        str([dict(z) for z in _full_k]))
auth_k.store._exec("UPDATE session SET last_seen = last_seen - 30 * 86400")
r.check("… and so after password + TOTP still only the absolute lifetime applies",
        ckk.get("/inside", follow_redirects=False).status_code == 200)
# (Mutation probe: delete the transfer in `_successor` → both red.)

# ── Limits a–e from the integration attack (PO: build) ─────────────────────────────────
import re as _re  # noqa: E402
import pyotp  # noqa: E402

# (a) A complete sign-in clears only failed attempts from the creation of the account.
auth_a8, app_a8 = _app()
for _ in range(3):
    auth_a8._record_login("before@example.com", "198.51.100.20", False, "password")
auth_a8.store._exec("UPDATE login_attempt SET ts = ts - 3600")
uid_a8 = auth_a8.create_user("neukonto", password=PW, email="before@example.com")
_login(TestClient(app_a8), "neukonto", PW)
r.check("Limit a: failed attempts under the address from BEFORE the creation remain after the first login",
        auth_a8.store.count_fails(0, username="before@example.com") == 3,
        str(auth_a8.store.count_fails(0, username="before@example.com")))
auth_a8._record_login("neukonto", "198.51.100.21", False, "password")
_login(TestClient(app_a8), "neukonto", PW)
r.check("… it clears the account's own (after the creation) as before",
        auth_a8.store.count_fails(0, username="neukonto") == 0)

# (b) The panel distinguishes the two locks.
auth_b8, app_b8 = _app()
auth_b8.create_user("panelchef", password=PW, is_admin=True)
waits = auth_b8.create_user("waits", password=PW)
concerning = auth_b8.create_user("operator-locked", password=PW)
auth_b8.store.set_disabled(waits, True)
auth_b8.store.set_disabled(concerning, True, through_operator=True)
cb8 = TestClient(app_b8)
_login(cb8, "panelchef", PW)
items = {u["username"]: u for u in cb8.get("/auth/admin/api/users").json()}
r.check("Limit b: the panel names the reason for the lock (confirmation/app vs. operator)",
        items["waits"]["disabled_by"] == "confirmation" and items["operator-locked"]["disabled_by"] == "operator"
        and items["panelchef"]["disabled_by"] is None, str({k: v["disabled_by"] for k, v in items.items()}))

# (c) The audit searches run via an index.
_plan = auth_b8.store.db.execute(
    "EXPLAIN QUERY PLAN SELECT id FROM audit WHERE event IN ('signup','signup_taken') "
    "AND lower(username) = lower(?) AND ts BETWEEN ? AND ?", ("x", 1, 2)).fetchall()
r.check("Limit c: `setup_limit` searches via the index instead of through the whole audit log",
        any("idx_audit_name_ts" in str(tuple(z)) for z in _plan), str([tuple(z) for z in _plan]))

# (d) Chain password → totp → pin with mandatory enrollment: the offer to end the other sessions
#     is redeemed as soon as the chain is complete.
auth_d8, app_d8 = _app(login_chain=["password", "totp", "pin"], pin_enabled=True)
uid_d8 = auth_d8.create_user("chain", password=PW)
auth_d8.set_pin(uid_d8, "4812")
old_token = auth_d8.store.create_session(uid_d8, 3600, True, "password")   # the lost device
cd8 = TestClient(app_d8)
_login(cd8, "chain", PW)
_page_html = cd8.post("/auth/totp/setup/start", data={"next": "/"})
_secret_text = _re.search(r"secret=([A-Z2-7]+)", _page_html.text) or _re.search(r"\b([A-Z2-7]{32})\b", _page_html.text)
_confirmed = cd8.post("/auth/totp/setup", data={"code": pyotp.TOTP(_secret_text.group(1)).now(), "next": "/"}).json()
r.check("Limit d: the enrollment in the middle of the chain reports the other sessions (other_sessions_after)",
        _confirmed.get("ok") and _confirmed.get("other_sessions_after") == 1, str(_confirmed))
_note = cd8.post("/auth/sessions/revoke-after-login", json={})
r.check("… the consent is noted, but nothing is ended yet",
        _note.status_code == 200 and auth_d8.store.get_session(old_token) is not None)
cd8.post("/auth/pin", data={"username": "chain", "pin": "4812"}, follow_redirects=False)   # half session: with name
r.check("… and with the last factor (PIN) the other sessions end",
        auth_d8.store.get_session(old_token) is None and cd8.get("/auth/me").status_code == 200)
auth_v8, app_v8 = _app()                                      # without chain: password = full session
auth_v8.create_user("full", password=PW)
cfull = TestClient(app_v8)
_login(cfull, "full", PW)
r.check("… a full session cannot set the note (that is what /auth/sessions/revoke is for)",
        cfull.post("/auth/sessions/revoke-after-login", json={}).status_code in (400, 401))

# (e) Revoking API keys notifies the owner.
auth_e8, app_e8 = _app()
events = []
auth_e8.on_security_event = lambda event, account, details: events.append((event, details))
uid_e8 = auth_e8.create_user("keyhalter", password=PW)
k1 = auth_e8.create_api_key(uid_e8, name="ci")
auth_e8.revoke_api_key(k1["id"])
auth_e8.revoke_api_key(k1["id"])                              # twice: only one event
auth_e8.create_api_key(uid_e8, name="a")
auth_e8.create_api_key(uid_e8, name="b")
auth_e8._keys_revoked(uid_e8, "sessions_revoked")
names = [e for e, _ in events]
r.check("Limit e: a single revocation reports api_key_revoked (exactly once)",
        names.count("api_key_revoked") == 1, str(names))
r.check("… a collective one reports api_keys_revoked with count",
        ("api_keys_revoked", {"count": 2, "reason": "sessions_revoked"}) in events, str(events))
boss_e8 = auth_e8.create_user("chef-e8", password=PW, is_admin=True)
auth_e8.create_api_key(uid_e8, name="c")
ce8 = TestClient(app_e8)
_login(ce8, "chef-e8", PW)
ce8.post(f"/auth/admin/api/users/{uid_e8}/disable", json={"disabled": True})
r.check("… also when locking in the panel", ("api_keys_revoked", {"count": 1, "reason": "account_disabled"}) in events,
        str(events[-2:]))
# (Mutation probes: delete `seit=since` in `lift_lockout` → (a) red; fix `disabled_by` to
#  None → (b) red; delete index → (c) red; `_other_after_completion` empty → (d) red;
#  delete `security_event` in `_keys_revoked` → (e) red.)

# ── B1-12 / ASVS 6.3.8: registration reveals no addresses (not even in the runtime) ─────
def _reg_app():
    a, app = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                  login_identifier="email")
    a.set_mailer(lambda to, subject, text, html=None: None)
    return a, app


a638, app638 = _reg_app()
a638.create_user("taken@example.com", password=PW, email="taken@example.com")
_counter = {"n": 0}
_orig_exec = a638.store._exec


def _counting(sql, args=()):
    _counter["n"] += 1
    return _orig_exec(sql, args)


a638.store._exec = _counting
c638 = TestClient(app638)
_counter["n"] = 0
free = c638.post("/auth/register", data={"email": "free@example.com", "password": FIFTEEN + "x"})
_n_free = _counter["n"]
_counter["n"] = 0
grant = c638.post("/auth/register", data={"email": "taken@example.com", "password": FIFTEEN + "x"})
_n_grant = _counter["n"]
a638.store._exec = _orig_exec
r.check("ASVS 6.3.8: free and taken address respond the same (status and page)",
        free.status_code == grant.status_code == 200
        and _re.sub(r"nonce=\"[^\"]+\"", "", free.text) == _re.sub(r"nonce=\"[^\"]+\"", "", grant.text),
        f"{free.status_code}/{grant.status_code}")
r.check("… and do the same work in the request (equally many writes — no timing oracle)",
        _n_free == _n_grant, f"free {_n_free}, granted {_n_grant}")
_place = [u for u in a638.store.list_users() if str(u["username"]).startswith("reserved-")]
r.check("… the placeholder is locked, carries no address and disappears with gc()",
        len(_place) == 1 and _place[0]["disabled"] and not _place[0]["email"])
from tinysesam import config_check as _kp  # noqa: E402
_, _w638 = _kp.check_config(TinySesamConfig(db_path=":memory:", base_url="https://app.example", allow_signup=True,
                                      signup_require_email=True))
r.check("… without confirmation this does not work — the configuration check says so (6.3.8)",
        any("6.3.8" in w for w in _w638), str(_w638)[:200])
# (Mutation probe: only `hash_password` instead of placeholder in the taken branch again → writes red.)

# ── B1-12 / ASVS 6.3.5: notice to the owner when their account is locked ──────────────────
def _notice_app(**cfg):
    a, app = _app(**cfg)
    post = []
    a.set_mailer(lambda to, subject, text, html=None: post.append((to, subject, text)))
    return a, app, post


a635, app635, post635 = _notice_app()
a635.create_user("holder-f", password=PW, email="holder-f@example.com")
for _ in range(a635._sec("max_login_attempts") + 2):
    _login(TestClient(app635), "holder-f", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
a635._notice_outcome.wait()
r.check("ASVS 6.3.5: with configured mail delivery the owner gets a notice (default on, opt-out)",
        len(post635) == 1 and post635[0][0] == "holder-f@example.com", str(post635))
r.check("… the notice carries no link (there is no base an attacker could bend)",
        post635 and "://" not in post635[0][2], post635[0][2][:120] if post635 else "")
r.check("… exactly one per lock window, not one per rejected attempt",
        len(post635) == 1 and any(z["event"] == "lockout_notice" for z in a635.store.recent_audit(50)))
for _ in range(a635._sec("max_login_attempts") + 2):
    _login(TestClient(app635), "nobody", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
a635._notice_outcome.wait()
r.check("… an unknown name triggers nothing (and the same happens in the request)", len(post635) == 1)
a635u, app635u, post635u = _notice_app()
_u = a635u.create_user("free", password=PW, email="free@example.com")
a635u.store.set_email_verified(_u, False)
for _ in range(a635u._sec("max_login_attempts") + 2):
    _login(TestClient(app635u), "free", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
a635u._notice_outcome.wait()
r.check("… nothing goes to an UNPROVEN address (H-3)", post635u == [], str(post635u))
a635o, app635o, post635o = _notice_app(notify_login_failures=False)
a635o.create_user("still", password=PW, email="still@example.com")
for _ in range(a635o._sec("max_login_attempts") + 2):
    _login(TestClient(app635o), "still", f"wrong-wrong-wrong-xxx{next(_WRONG)}")
a635o._notice_outcome.wait()
r.check("… opt-out: notify_login_failures=False sends nothing", post635o == [], str(post635o))
# (Mutation probes: do not call `_lockout_notice` in `_rejected` → first check red; delete the
#  throttle → "exactly one" red; delete `_proof_on_account` → "UNPROVEN" red.)

# ── H-14/H-15: TOTP secrets encrypted at rest (mandatory) ────────────────────────────────
import base64 as _b64  # noqa: E402
import os as _os  # noqa: E402
import stat as _stat  # noqa: E402

a14, app14 = _app()
u14 = a14.create_user("totpnutzer", password=PW)
secret_text14 = a14.totp_begin(u14)["secret"]
raw14 = a14.store._one("SELECT secret FROM totp_cred WHERE user_id=?", (u14,))["secret"]
r.check("H-14/15: in the database the TOTP secret is stored encrypted, not in plaintext",
        raw14.startswith("v1:") and secret_text14 not in raw14, raw14[:20])
r.check("… and signing in with it works (setup with a real code)",
        a14.totp_confirm(u14, pyotp.TOTP(secret_text14).now()))
_key_file = a14.cfg.db_path + ".key"
r.check("… without a setting the key lies next to the database, readable only by the owner (0600)",
        _os.path.isfile(_key_file) and _stat.S_IMODE(_os.stat(_key_file).st_mode) == 0o600)

# Existing data: a plaintext secret is encrypted at startup (silent lift).
_path14 = a14.cfg.db_path
a14.store._exec("UPDATE totp_cred SET secret=? WHERE user_id=?", (secret_text14, u14))   # as before 0.21
a14.store.db.close()
a14b, _ = _app(db_path=_path14)
roh14b = a14b.store._one("SELECT secret FROM totp_cred WHERE user_id=?", (u14,))["secret"]
r.check("H-14/15: a plaintext secret from before is encrypted at startup",
        roh14b.startswith("v1:") and a14b.store.get_totp(u14)["secret"] == secret_text14)
a14b.store.db.close()

# Wrong key → startup aborts instead of silently letting every TOTP sign-in fail.
_os.environ["TINYSESAM_SECRETS_KEY"] = _b64.b64encode(_os.urandom(32)).decode()
try:
    _app(db_path=_path14)
    _wrong = False
except ConfigError:
    _wrong = True
finally:
    del _os.environ["TINYSESAM_SECRETS_KEY"]
r.check("H-14/15: a key that does not fit aborts startup (ConfigError)", _wrong)

# Precedence: environment before file before "next to the database"; a broken value is an error.
_file14 = str(Path(tempfile.mkdtemp()) / "key")
with open(_file14, "w") as _f:
    _f.write(_b64.b64encode(_os.urandom(32)).decode())
a14c, _ = _app(secrets_key_file=_file14)
r.check("… secrets_key_file is taken, then no file next to the database is created",
        a14c._key_name_origin == "file" and not _os.path.exists(a14c.cfg.db_path + ".key"))
with open(_file14, "w") as _f:
    _f.write("to-short")
try:
    _app(secrets_key_file=_file14)
    _broken = False
except ConfigError:
    _broken = True
r.check("… a broken key (not Base64 of 32 bytes) is an error, no silent replacement", _broken)
# (Mutation probes: store `set_totp` unencrypted → first check red; remove the key probe
#  in `extract_secrets` → "aborts startup" red; remove the lifting → "plaintext …
#  is encrypted at startup" red.)



def _now_minus(auth):
    """Seconds until the next re-check of the (single) OIDC session."""
    import time as _t
    z = auth.store._one("SELECT checked_at FROM oidc_session")
    return int(z["checked_at"]) + int(auth.cfg.oidc_session_refresh_minutes) * 60 - int(_t.time())


# ── 4a: revocation follows the provider (refresh token every N minutes) ─────────────────────
a4a, app4a = _oidc({"sub": "r-1", "preferred_username": "refresher", "groups": ["admins"]},
                   oidc_group_role_map=MAP)
a4a.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
    _Claims({"sub": "r-1", "preferred_username": "refresher", "groups": ["admins"], "nonce": nonce}),
    {"access_token": "at", "refresh_token": "rt-1"})
_responses = []
_called = []


def _refresh(rt, sub):
    _called.append((rt, sub))
    return _responses.pop(0)


a4a.oidc.refresh = _refresh
c4a = TestClient(app4a, raise_server_exceptions=False)
_start = c4a.get("/auth/oidc/start", follow_redirects=False)
_st = parse_qs(urlparse(_start.headers["location"]).query)["state"][0]
c4a.get(f"/auth/oidc/callback?code=x&state={_st}", follow_redirects=False)
_roh4a = a4a.store._one("SELECT refresh FROM oidc_session")
r.check("4a: the refresh token is stored with the session, encrypted",
        _roh4a is not None and _roh4a["refresh"].startswith("v1:") and "rt-1" not in _roh4a["refresh"])
r.check("… within the period TinySesam does not ask the provider",
        c4a.get("/auth/me").status_code == 200 and _called == [])


def _alternate():
    a4a.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60")


_uid4a = a4a.store.get_user_by_name("refresher")["id"]
_alternate()
_responses.append(("ok", {"sub": "r-1", "groups": ["admins"]}, {"refresh_token": "rt-2"}))
_first = c4a.get("/auth/me").status_code
a4a._oidc_outcome.wait()                                  # the exchange happens in the background (finding 6)
r.check("4a: after the period it is exchanged; the provider says yes → the session stays",
        _first == 200 and c4a.get("/auth/me").status_code == 200 and _called == [("rt-1", "r-1")])
r.check("… a newly issued refresh token replaces the old one (rotation)",
        a4a.store.get_oidc_session(a4a.store._one("SELECT token_hash FROM oidc_session")["token_hash"])["refresh"] == "rt-2")
_alternate()
_responses.append(("ok", {"sub": "r-1", "groups": []}, {}))
c4a.get("/auth/me")
a4a._oidc_outcome.wait()
r.check("4a + H-5: if the provider takes away the admin group, the flag is gone within the period — not only at login",
        not a4a.store.get_user(_uid4a)["is_admin"])
_alternate()
_responses.append(("ok", {"sub": "r-1"}, {}))                   # no groups claim
a4a.set_roles(_uid4a, ["editor"])
c4a.get("/auth/me")
a4a._oidc_outcome.wait()
r.check("… if the groups claim is missing entirely, the roles stay (missing ≠ no groups)",
        "editor" in a4a.user_roles(a4a.store.get_user(_uid4a)))
_alternate()
_responses.append(("error", {}, {"error": "ConnectError"}))
c4a.get("/auth/me")
a4a._oidc_outcome.wait()
r.check("4a: if the provider is unreachable, the session stays (an outage signs nobody out)",
        c4a.get("/auth/me").status_code == 200)
r.check("… and it is retried within a minute, not only after the full period",
        _now_minus(a4a) <= 15 * 60 - 60 + 5)
_alternate()
_responses.append(("rejected", {}, {"error": "invalid_grant"}))
c4a.get("/auth/me")
a4a._oidc_outcome.wait()
r.check("4a: if the provider refuses (locked, deleted, withdrawn), the session is gone",
        c4a.get("/auth/me").status_code == 401
        and a4a.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0
        and any(z["event"] == "oidc_revoked" for z in a4a.store.recent_audit(20)))
a4b, app4b = _oidc({"sub": "r-2", "preferred_username": "without"}, oidc_session_refresh_minutes=0)
a4b.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
    _Claims({"sub": "r-2", "preferred_username": "without", "nonce": nonce}),
    {"access_token": "at", "refresh_token": "rt-x"})
_oidc_login(app4b)
r.check("4a configurable: oidc_session_refresh_minutes=0 stores nothing",
        a4b.store._one("SELECT COUNT(*) AS n FROM oidc_session")["n"] == 0)
# (Mutation probes: `_oidc_recheck` always True → "session gone" red; remove the group re-evaluation
#  → "flag … gone" red; remove `in info` → "missing ≠ no groups" red; remove the
#  retry within a minute → "within a minute" red.)

# ── Findings from the attack on the second round (4a, key, idle, notice) ─────────────────────
import threading as _th  # noqa: E402
import time as _when  # noqa: E402


def _oidc_with_refresh(sub, claims=None, **cfg):
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
a5r, _, c5r = _oidc_with_refresh("parallel")
_swap = []
a5r.oidc.refresh = lambda rt, sub: (_swap.append(rt) or ("ok", {"sub": sub}, {}))
a5r.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60")
_s5 = a5r.store._one("SELECT * FROM session")
for _ in range(4):
    a5r._oidc_recheck(_s5)
a5r._oidc_outcome.wait()
r.check("Finding 5: four requests after the period exchange the refresh token exactly once", len(_swap) == 1,
        str(_swap))

# Finding 6: a hanging provider does not hold up the request.
a6r, _, c6r = _oidc_with_refresh("hangs")
a6r.oidc.refresh = lambda rt, sub: (_when.sleep(1.5), ("ok", {"sub": sub}, {}))[1]
a6r.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60")
_t0 = _when.monotonic()
_st6 = c6r.get("/auth/me").status_code
_duration = _when.monotonic() - _t0
a6r._oidc_outcome.wait()
r.check("Finding 6: the request does not wait for the provider (exchange in the background)",
        _st6 == 200 and _duration < 1.0, f"{_duration:.2f}s")

# Finding 7: one row per client — a login via a second client does not overwrite the first.
_h7 = a6r.store._one("SELECT token_hash FROM oidc_session")["token_hash"]
a6r.store.set_oidc_session(_h7, "app-b", "hangs", "rt-b")
r.check("Finding 7: several clients of one session — every row stays and is re-checked",
        {z["client"] for z in a6r.store.get_oidc_sessions(_h7)} == {"*", "app-b"})

# Finding 13: nobody asks the provider about a locked account.
a13, _, c13 = _oidc_with_refresh("locked13xx")
_t13 = []
a13.oidc.refresh = lambda rt, sub: (_t13.append(rt) or ("ok", {"sub": sub, "groups": ["admins"]}, {}))
a13.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60")
a13.store._exec("UPDATE users SET disabled = 2")
c13.get("/auth/me")
a13._oidc_outcome.wait()
r.check("Finding 13: nothing is exchanged for a locked account (F-17)", _t13 == [], str(_t13))

# Finding 4: a wrong key aborts startup even when there are only refresh tokens.
_path4 = a5r.cfg.db_path
a5r.store.db.close()
_os.environ["TINYSESAM_SECRETS_KEY"] = _b64.b64encode(_os.urandom(32)).decode()
try:
    _oidc({"sub": "x"}, db_path=_path4)
    _f4 = False
except ConfigError:
    _f4 = True
finally:
    del _os.environ["TINYSESAM_SECRETS_KEY"]
r.check("Finding 4: wrong key + only OIDC refresh tokens → startup aborts", _f4)

# Finding 9: the 8-h limit applies to every session without an EXPLICIT "stay signed in".
a9, app9, c9 = _oidc_with_refresh("idle9")
a9.store._exec("UPDATE session SET last_seen = last_seen - 9 * 3600")
r.check("Finding 9: an OIDC session (persistent, but without choice) ends after 8 h of inactivity",
        c9.get("/auth/me").status_code == 401)

# Finding 10: several workers create the key at the same time — all get the same one.
from tinysesam import vault as _gh  # noqa: E402
_db10 = str(Path(tempfile.mkdtemp()) / "race.db")
_erg10, _error10 = [], []


def _load10():
    try:
        _erg10.append(_gh.load_key(_db10)[0])
    except Exception as e:   # noqa: BLE001
        _error10.append(repr(e))


_threads = [_th.Thread(target=_load10) for _ in range(24)]
for _f in _threads:
    _f.start()
for _f in _threads:
    _f.join()
r.check("Finding 10: 24 simultaneous first starts — no error, a single key",
        not _error10 and len(set(_erg10)) == 1 and len(_erg10) == 24, f"{_error10[:2]} / {len(set(_erg10))}")

# Finding 11: the throttle of the lock notice lives in the database — an evicted memory key
# (or a second worker) sends no second one.
a11, app11, post11 = _notice_app()
a11.create_user("throttled", password=PW, email="throttled@example.com")
a11._lockout_notice("throttled", "198.51.100.30", "lockout_user")
a11._notice_outcome.wait()
a11.rl.allow = lambda *a, **k: True                             # as after the eviction
a11._lockout_notice("throttled", "198.51.100.31", "lockout_user")
a11._notice_outcome.wait()
r.check("Finding 11: even without the memory throttle at most one notice per lock window", len(post11) == 1,
        str(len(post11)))
# (Mutation probes: remove the claim in `_oidc_recheck` → finding 5 red; the exchange
#  synchronous instead of via `_oidc_outcome` → finding 6 red; remove the audit throttle in `_send` →
#  finding 11 red; remove `stay_chosen` in `get_session` → finding 9 red.)

# ── Finding 8: API keys follow the identity provider (PO decision 2026-09-24) ─────────────
# If the provider says no (4a), the keys of the OIDC account rest; likewise without confirmation within
# `oidc_apikey_confirm_days`. Nothing is deleted — the next sign-in wakes them.
def _again_over_idp(c):
    st = parse_qs(urlparse(c.get("/auth/oidc/start", follow_redirects=False).headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={st}", follow_redirects=False)


a8, app8, c8 = _oidc_with_refresh("keyhalter")
uid8 = a8.store.get_user_by_name("keyhalter")["id"]
key8 = a8.create_api_key(uid8, name="backup")["key"]
r.check("Finding 8: the key of an account freshly signed in via the provider is valid",
        a8.verify_api_key(key8)[0] is not None)
a8.oidc.refresh = lambda rt, sub: ("rejected", {}, {"error": "invalid_grant"})
a8.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60")
a8._oidc_recheck(a8.store._one("SELECT * FROM session"))
a8._oidc_outcome.wait()
r.check("Finding 8: after the provider's no the key rests (session gone, key rejected)",
        a8.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0 and a8.verify_api_key(key8)[0] is None)
_line8 = a8.store._one("SELECT detail FROM audit WHERE event='api_keys_dormant'")
r.check("… with a row in the audit log (how many keys it affects)",
        _line8 is not None and "count=1" in _line8["detail"], str(_line8 and dict(_line8)))
r.check("… nothing is deleted or revoked",
        not a8.store._one("SELECT revoked FROM api_key")["revoked"])
# The no is stored as a NEGATIVE timestamp; a yes only wakes if its question went out afterwards. Here
# the no is five seconds old, the sign-in starts now.
a8.store._exec("UPDATE users SET idp_confirmed_at = ? WHERE id=?", (-(int(_when.time()) - 5), uid8))
r.check("… and the next sign-in via the provider wakes it again",
        _again_over_idp(c8).status_code == 303 and a8.verify_api_key(key8)[0] is not None)
# The race: the question went out BEFORE the no (two sessions, two workers), but the yes is
# applied afterwards. It must not overwrite the no.
a8.store.idp_refused(uid8)
_question_before = int(_when.time()) - 10
r.check("Finding 8: a yes whose question went out BEFORE the no does not wake the keys (race)",
        not a8.store.confirm_idp(uid8, _question_before) and a8.verify_api_key(key8)[0] is None)
a8.store._exec("UPDATE users SET idp_confirmed_at = ? WHERE id=?", (-(int(_when.time()) - 5), uid8))
r.check("… one whose question went out afterwards does",
        a8.store.confirm_idp(uid8, int(_when.time())) and a8.verify_api_key(key8)[0] is not None)

# Period without session (script-only): 30 days default.
a8.store._exec("UPDATE users SET idp_confirmed_at = ? WHERE id=?", (int(_when.time()) - 29 * 86400, uid8))
_inside8 = a8.verify_api_key(key8)[0] is not None
a8.store._exec("UPDATE users SET idp_confirmed_at = ? WHERE id=?", (int(_when.time()) - 31 * 86400, uid8))
r.check("Finding 8: without confirmation within 30 days the key rests (29 days: valid, 31: rests)",
        _inside8 and a8.verify_api_key(key8)[0] is None)
a8.cfg.oidc_apikey_confirm_days = 0
_without_deadline8 = a8.verify_api_key(key8)[0] is not None
a8.store.idp_refused(uid8)
r.check("… `oidc_apikey_confirm_days=0` switches off only the period — the no still counts",
        _without_deadline8 and a8.verify_api_key(key8)[0] is None)
a8.cfg.oidc_apikey_confirm_days = 30

# A yes at the exchange confirms; a group withdrawal is a no.
a8b, app8b, c8b = _oidc_with_refresh("group8", claims={"groups": ["team"]}, oidc_allowed_groups=["team"])
uid8b = a8b.store.get_user_by_name("group8")["id"]
key8b = a8b.create_api_key(uid8b, name="ci")["key"]
a8b.store._exec("UPDATE users SET idp_confirmed_at = 1000 WHERE id=?", (uid8b,))
a8b.oidc.refresh = lambda rt, sub: ("ok", {"sub": sub, "groups": ["team"]}, {})
a8b.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60")
a8b._oidc_recheck(a8b.store._one("SELECT * FROM session"))
a8b._oidc_outcome.wait()
r.check("Finding 8: a yes at the refresh exchange confirms the account (the old state becomes fresh)",
        a8b.store.get_user(uid8b)["idp_confirmed_at"] > 1000 and a8b.verify_api_key(key8b)[0] is not None)
a8b.oidc.refresh = lambda rt, sub: ("ok", {"sub": sub, "groups": ["other"]}, {})
a8b.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60")
a8b._oidc_recheck(a8b.store._one("SELECT * FROM session"))
a8b._oidc_outcome.wait()
r.check("… withdrawal of the allowed group is a no: the key rests",
        a8b.verify_api_key(key8b)[0] is None and a8b.store.get_user(uid8b)["idp_confirmed_at"] < 0)

# Accounts without an OIDC binding are not affected — not even with a state that would mean "no".
local8 = a8.create_user("local8", password=PW)
key8l = a8.create_api_key(local8, name="local")["key"]
a8.store._exec("UPDATE users SET idp_confirmed_at = 0 WHERE id=?", (local8,))
r.check("Finding 8: an account without an OIDC binding keeps its key (even with idp_confirmed_at=0)",
        a8.verify_api_key(key8l)[0] is not None)

# Existing data: the period starts with the update, exactly once.
_path8 = str(Path(tempfile.mkdtemp()) / "existing8.db")
_old8 = Store(_path8)
_old8.create_user("existing-oidc", None, None, False, [], False)
_old8.link_oidc("https://idp.example", "sub-b", 1)
_old8.db.execute("ALTER TABLE users DROP COLUMN idp_confirmed_at")
_old8.db.execute("DELETE FROM setting WHERE key='idp_inventory_set'")   # a 0.20 file does not know it
_old8.db.commit()
_old8.db.close()
_new8 = Store(_path8)
_state8 = _new8.get_user(1)["idp_confirmed_at"]
# Afterwards without state (an account bound by a route without confirmation): a restart
# must NOT grant it a fresh period.
_new8.db.execute("UPDATE users SET idp_confirmed_at = NULL WHERE id=1")
_new8.db.commit()
_new8.db.close()
r.check("Finding 8, existing data: the period of an OIDC account starts with the update — and only once",
        _state8 is not None and abs(_state8 - int(_when.time())) < 60
        and Store(_path8).get_user(1)["idp_confirmed_at"] is None, f"{_state8}")
# Abort in the middle of the update: the column is already there (the ALTER is durable immediately), state and
# marker are not. The next start catches up.
_pfad8c = str(Path(tempfile.mkdtemp()) / "abort8.db")
_from8 = Store(_pfad8c)
_from8.create_user("abort-oidc", None, None, False, [], False)
_from8.link_oidc("https://idp.example", "sub-c", 1)
_from8.db.execute("DELETE FROM setting WHERE key='idp_inventory_set'")
_from8.db.commit()
_from8.db.close()
r.check("Finding 8, existing data: after an abort (column present, marker not) the next start sets the state",
        Store(_pfad8c).get_user(1)["idp_confirmed_at"] is not None)
# (Mutation probes: remove `_key_rests` in `verify_api_key` → "rests" red; remove `confirm_idp` in the
#  callback → "wakes it again" red; remove the period check → "31: rests" red;
#  remove `_idp_no` in the group branch → group withdrawal red; remove the binding check →
#  "without OIDC binding" red; the existing-data line at every start → "only once" red.)


# ── 3c · ASVS 6.3.6: the sign-in link needs the second factor when there is one ─────────────
def _link_app(**cfg):
    a, ap = _app(magiclink_enabled=True, **cfg)
    a.set_mailer(lambda *x, **k: True)

    @ap.get("/inside")
    def _inside(user=Depends(a.require())):
        return {"u": user["username"]}
    return a, ap


def _link_login(a, ap, name):
    c = TestClient(ap)
    uid = a.store.get_user_by_name(name)["id"]
    tok = a.create_magic_token("login", user_id=uid, payload={"next": "/inside"})
    return c, c.post(f"/auth/magic/{tok}", follow_redirects=False)


# Classic (no chain), account with passkey only: up to here the link alone signed in fully.
a3c, ap3c = _link_app()
u3c = a3c.create_user("passkey-account", password=PW, email="pk@example.com")
a3c.store.add_webauthn(u3c, b"cred-3c", b"pub", 0, "[]", "Laptop")
c3c, antw3c = _link_login(a3c, ap3c, "passkey-account")
r.check("3c: account with passkey — the link alone does not sign in fully (continue to the passkey)",
        antw3c.status_code == 303 and antw3c.headers["location"].startswith(a3c.cfg.login_path)
        and c3c.get("/inside", follow_redirects=False).status_code != 200,
        f"{antw3c.status_code} {antw3c.headers.get('location')}")
# Chain ["magic"] with TOTP: the link satisfied the chain, the authenticator did not count.
a3k, ap3k = _link_app(login_chain=["magic"])
u3k = a3k.create_user("totp-account", password=PW, email="tk@example.com")
_g3k = a3k.totp_begin(u3k)["secret"]
a3k.totp_confirm(u3k, pyotp.TOTP(_g3k).at(_when.time() - 30))
c3k, antw3k = _link_login(a3k, ap3k, "totp-account")
r.check("3c: chain [\"magic\"], account with TOTP — the TOTP step follows the link",
        antw3k.status_code == 303 and antw3k.headers["location"].startswith("/auth/totp")
        and c3k.get("/inside", follow_redirects=False).status_code != 200,
        f"{antw3k.status_code} {antw3k.headers.get('location')}")
_fertig3k = c3k.post("/auth/totp", data={"code": pyotp.TOTP(_g3k).now(), "next": "/inside"},
                     follow_redirects=False)
r.check("… with the code the sign-in is complete",
        _fertig3k.status_code == 303 and c3k.get("/inside").json() == {"u": "totp-account"})
a3o, ap3o = _link_app(login_chain=["magic"])
a3o.create_user("without-factor", password=PW, email="of@example.com")
c3o, _ = _link_login(a3o, ap3o, "without-factor")
r.check("3c: an account without a second factor is still signed in by the link alone (C, not D)",
        c3o.get("/inside").json() == {"u": "without-factor"})
a3a, ap3a = _link_app(login_chain=["magic"], magiclink_require_second_factor=False)
u3a = a3a.create_user("totp-a", password=PW, email="ta@example.com")
_g3a = a3a.totp_begin(u3a)["secret"]
a3a.totp_confirm(u3a, pyotp.TOTP(_g3a).at(_when.time() - 30))
c3a, _ = _link_login(a3a, ap3a, "totp-a")
r.check("3c configurable: magiclink_require_second_factor=False — the link suffices again (A)",
        c3a.get("/inside").json() == {"u": "totp-a"})
_pw3 = TestClient(ap3k)
_pw3.post("/auth/login", data={"username": "totp-account", "password": PW, "next": "/inside"},
          follow_redirects=False)
r.check("… other routes stay as they were (password alone in the chain [\"magic\"]: no login)",
        _pw3.get("/inside", follow_redirects=False).status_code != 200)
# (Mutation probes: remove `_link_requires` in `_session_ok` → the first two red; remove the
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


def _with_totp(a, name):
    uid = a.create_user(name, password=PW, email=f"{name}@example.com")
    secret_text = a.totp_begin(uid)["secret"]
    a.totp_confirm(uid, pyotp.TOTP(secret_text).at(_when.time() - 30))
    return secret_text


_JSON, _HTML10 = {"accept": "application/json"}, {"accept": "text/html"}
a10, ap10 = _route_app()
_g10 = _with_totp(a10, "rt-totp")
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
_g10g = _with_totp(a10g, "rt-totp")
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
a10o.create_user("rt-without", password=PW, email="rto@example.com")
r.check("G10: without a second factor the link still opens the route alone (C, not D)",
        _route_link(a10o, ap10o, "rt-without").get("/r", headers=_JSON).json() == {"u": "rt-without"})
# magiclink_require_second_factor=False switches off the rule of the sign-in link — not the global one:
# the classic policy demands a set-up TOTP anyway, and a route chain no longer falls below
# it since 2026-09-27. Measured on the account with passkey only (only the link rule demands it).
a10a, ap10a = _route_app(magiclink_require_second_factor=False)
_u10a = a10a.create_user("rt-aus", password=PW, email="rta@example.com")
a10a.store.add_webauthn(_u10a, b"cred-g10a", b"pub", 0, "[]", "Laptop")
r.check("G10: magiclink_require_second_factor=False applies here too — the link suffices for the route (account with passkey)",
        _route_link(a10a, ap10a, "rt-aus").get("/r", headers=_JSON).json() == {"u": "rt-aus"})
_with_totp(a10a, "rt-aus-totp")
_j10a = _route_link(a10a, ap10a, "rt-aus-totp").get("/r", headers=_JSON)
r.check("… a set-up TOTP is demanded by the classic rule anyway (the route does not fall below it)",
        _j10a.status_code == 401 and _j10a.headers.get("x-tinysesam-factor") == "totp",
        f"HTTP {_j10a.status_code} {_j10a.headers.get('x-tinysesam-factor')}")
a10k, ap10k = _route_app()
_g10k = _with_totp(a10k, "rt-chain")
c10k = _route_link(a10k, ap10k, "rt-chain")
_prior10k = c10k.get("/r2", headers=_JSON)
c10k.post("/auth/totp", data={"code": pyotp.TOTP(_g10k).now(), "next": "/r2"}, follow_redirects=False)
r.check("G10: route [\"magic\", \"totp\"] — exactly one TOTP step, then open (no double step)",
        _prior10k.status_code == 401 and _prior10k.headers.get("x-tinysesam-factor") == "totp"
        and c10k.get("/r2", headers=_JSON).json() == {"u": "rt-chain"},
        f"HTTP {_prior10k.status_code} {_prior10k.headers.get('x-tinysesam-factor')}")
# (Mutation probe, executed: switch off the call of `_link_requires` in
#  `_enforce_route_chain` → the TOTP, passkey and chain cases turn red.)

# ── Aligning route chains (PO decision 2026-09-27): a route chain only tightens ──────────────────
# Until then `require(factors=[…])` only checked its own list (and after G10 the link). A half
# session to which the GLOBAL rule still owed a factor got through: `factors=["password"]`
# opened the route of an account with TOTP after the password, `["pin", "password"]` after PIN and
# password likewise, and under `login_chain=["password", "totp"]` the password alone sufficed.
def _chain_app(**cfg):
    a, ap = _app(pin_enabled=True, **cfg)

    @ap.get("/pw")
    def _pw(user=Depends(a.require(factors=["password"]))):
        return {"u": user["username"]}

    @ap.get("/pinpw")
    def _pinpw(user=Depends(a.require(factors=["pin", "password"]))):
        return {"u": user["username"]}
    return a, ap


a_k, ap_k = _chain_app()
_g_k = _with_totp(a_k, "rk-totp")
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
a_ko, ap_ko = _chain_app()
a_ko.create_user("rk-without", password=PW)
c_ko = TestClient(ap_ko)
_login(c_ko, "rk-without", PW)
r.check("… without a second factor the session is full after the password — the route opens at once (control)",
        c_ko.get("/pw", headers=_JSON).json() == {"u": "rk-without"})
a_kc, ap_kc = _chain_app(login_chain=["password", "totp"])
a_kc.create_user("rk-chain", password=PW)
c_kc = TestClient(ap_kc)
_login(c_kc, "rk-chain", PW)
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
    def __init__(self, entries):
        self.e = entries

    def authenticate(self, username, password):
        z = self.e.get(username)
        return dict(z, username=username, groups=[]) if z and password == "x" else None


# S1 (high): SAML not trusted — a name that is the address of a local account does not bind it.
a_s1, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", login_identifier="email")
victim_s1 = a_s1.create_user("bob@example.com", password=PW, email="bob@example.com", is_admin=True)
new_s1 = a_s1._check_saml("bob@example.com", {"email": ["bob@example.com"]})
r.check("Attack R3/S1: SAML (not trusted) with the address of a local account as NameID does not take it over",
        new_s1 is not None and new_s1["id"] != victim_s1 and new_s1["username"].startswith("saml-")
        and not new_s1["is_admin"] and a_s1.store.get_federated_identifier("saml", victim_s1) is None,
        str(new_s1))
a_s1._check_saml("BOB@EXAMPLE.COM", {"email": ["bob@example.com"]})
r.check("… not in another spelling either", a_s1.store.get_federated_identifier("saml", victim_s1) is None)

# S3: without a stable identifier an address name is rejected — not a new account on every login.
a_s3, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", saml_attr_id="objectGUID")
_before_s3 = len(a_s3.store.list_users())
_e1 = a_s3._check_saml("anna@corp.example", {"email": ["anna@corp.example"]})
_e2 = a_s3._check_saml("anna@corp.example", {"email": ["anna@corp.example"]})
r.check("Attack R3/S3: SAML not trusted, address name without identifier → rejected, no account per login",
        _e1 is None and _e2 is None and len(a_s3.store.list_users()) == _before_s3)

# S2 (medium): LDAP not trusted, sign-in with an address (filter via mail).
a_s2, _ = _app(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False,
               login_identifier="both")
manager_s2 = a_s2.create_user("boss@example.com", password=PW, email="boss@example.com")
a_s2.ldap = _LDAP3({"boss@example.com": {"id": "uuid-mallory", "email": "boss@example.com", "name": "M"}})
_n_s2 = a_s2.store.user_count()
new_s2 = a_s2._check_ldap("boss@example.com", "x")
# Until 2026-09-27 this created an account `ldap-…`; since the review round (p1-d) the sign-in rejects —
# the address locally belongs to one account, the entry led to another.
r.check("Attack R3/S2: LDAP not trusted — the typed address neither becomes the account name nor binds an account",
        new_s2 is None and a_s2.store.user_count() == _n_s2
        and a_s2.store.get_federated_identifier("ldap", manager_s2) is None, str(new_s2))

# S4 (high, pre-existing): control characters in the account name.
a_s4, app_s4 = _app(allow_signup=True)
try:
    a_s4.create_user("boss\x01", password=PW)
    _s4_create = False
except ConfigError:
    _s4_create = True
_s4_reg = TestClient(app_s4).post("/auth/register", data={"username": "boss​", "password": PW + "xyz",
                                                         "next": "/"}, follow_redirects=False)
r.check("Attack R3/S4: no account with control/format characters in the name (create_user, registration)",
        _s4_create and _s4_reg.status_code == 400 and a_s4.store.get_user_by_name("boss​") is None,
        f"create={_s4_create} reg={_s4_reg.status_code}")
a_s4.create_user("boss", password=PW)
_old_s4 = a_s4.store.create_user("boss\x01", None, None, False, [], False)       # existing data past the latch
try:
    a_s4._forward_response_headers(a_s4.get_user(_old_s4))
    _s4_fwd = False
except _HTTPEx as e:
    _s4_fwd = e.status_code == 403
r.check("… and such existing data gets no remote user (fail-closed instead of `boss`)", _s4_fwd)
a_s4o, app_s4o = _oidc({"sub": "s4-sub", "preferred_username": "boss\x01", "email": "c4@example.com",
                        "email_verified": True})
_oidc_login(app_s4o)
_s4o = [u["username"] for u in a_s4o.store.list_users()]
r.check("… an IdP name with control characters is discarded (the proven address applies here)",
        _s4o == ["c4@example.com"], str(_s4o))
a_s4s, app_s4s = _oidc({"sub": "\x01s4", "preferred_username": ""})
_s4s_response = _oidc_login(app_s4s)
_s4s = [u["username"] for u in a_s4s.store.list_users()]
r.check("… and a `sub` with control characters yields a hashed substitute name, no rejection",
        _s4s_response.status_code == 303 and len(_s4s) == 1 and _s4s[0].startswith("oidc-")
        and "\x01" not in _s4s[0], f"{_s4s_response.status_code} {_s4s}")

# F8-2: errors of the client are no no for the account.
import httpx as _httpx3  # noqa: E402


class _Response3:
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
        _httpx3.post = lambda *a, _c=code, _b=body, **k: _Response3(_c, _b)
        _erg3[(code, body.get("error", "-"))] = _oc3.refresh("rt", "sub")[0]
finally:
    _httpx3.post = _post3
_should3 = {(401, "invalid_client"): "error", (400, "unauthorized_client"): "error",
          (400, "unsupported_grant_type"): "error", (401, "-"): "error", (503, "-"): "error",
          (400, "-"): "rejected", (400, "invalid_request"): "rejected",      # Dex: revoked token
          (400, "invalid_grant"): "rejected", (400, "access_denied"): "rejected"}
r.check("Attack R3/F8-2: client errors, 401 and 5xx → „fehler\"; every other 4xx (also Dex' invalid_request) → no",
        _erg3 == _should3, str({k: v for k, v in _erg3.items() if _should3.get(k) != v}))
# … and a row of a client that is no longer configured is discarded, not exchanged as a no.
a_f2, _, _ = _oidc_with_refresh("f2-account")
_uid_f2 = a_f2.store.get_user_by_name("f2-account")["id"]
_h_f2 = a_f2.store._one("SELECT token_hash FROM session")["token_hash"]
a_f2.store.set_oidc_session(_h_f2, "app-path", "f2-account", "rt-path")
a_f2.oidc.refresh = lambda rt, sub: ("rejected", {}, {"error": "invalid_grant"})     # the fallback said no
a_f2.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60 WHERE client='app-path'")
a_f2._oidc_recheck(a_f2.store._one("SELECT * FROM session"))
a_f2._oidc_outcome.wait()
r.check("… a row of a removed client goes, the session stays, the account gets no no",
        a_f2.store._one("SELECT COUNT(*) AS n FROM oidc_session WHERE client='app-path'")["n"] == 0
        and a_f2.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 1
        and (a_f2.store.get_user(_uid_f2)["idp_confirmed_at"] or 0) > 0)

# 3c/M1: chain ["magic","totp"], account with passkey without TOTP — the mailbox does not set up a TOTP for itself.
a_m1, ap_m1 = _link_app(login_chain=["magic", "totp"])
u_m1 = a_m1.create_user("pk-chain", password=PW, email="pkk@example.com")
a_m1.store.add_webauthn(u_m1, b"cred-m1", b"pub", 0, "[]", "Laptop")
c_m1, _ = _link_login(a_m1, ap_m1, "pk-chain")
_setup_m1 = c_m1.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False)
r.check("Attack R3/M1: sign-in link only + account with passkey → no TOTP self-setup",
        _setup_m1.status_code != 200 and not a_m1.store.has_confirmed_totp(u_m1)
        and any(z["event"] == "mfa_enrollment_denied" for z in a_m1.store.recent_audit(20)),
        f"HTTP {_setup_m1.status_code}")
a_m2, ap_m2 = _link_app(login_chain=["magic", "totp"])
a_m2.create_user("fresh-chain", password=PW, email="fk@example.com")
c_m2, _ = _link_login(a_m2, ap_m2, "fresh-chain")
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
# (Mutation probes are in the commit: ignore name_assign → S1 red; remove rejection without identifier →
#  S3 red; remove LDAP substitute name → S2 red; remove name_invalid in create_user → S4 red; header latch
#  removed → "fail-closed" red; client errors as a no again → F8-2 red; remove `known` → "removed
#  client" red; remove the passkey check in totp_enrollment_user → M1 red.)

# ── Counter-check of the fixes (third round): detours and regressions ──────────────────────
import logging as _log3  # noqa: E402

# V1: LDAP not trusted — a mail value WITHOUT "@" is just as unproven.
a_v1, _ = _app(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False)
manager_v1 = a_v1.create_user("boss", password=PW, is_admin=True)
a_v1.ldap = _LDAP3({"boss": {"id": "uuid-mallory", "email": "boss", "name": "M"}})
_n_v1 = a_v1.store.user_count()
new_v1 = a_v1._check_ldap("boss", "x")
# Until 2026-09-27 this created an account `ldap-…`; since the review round (p1-d) it rejects: the identifier
# `manager` locally belongs to one account, the entry led to another.
r.check("Counter-check R3/V1: LDAP not trusted, input = own mail value without „@\" → no takeover",
        new_v1 is None and a_v1.store.user_count() == _n_v1
        and a_v1.store.get_federated_identifier("ldap", manager_v1) is None, str(new_v1))
# V2: … and a UPN (bind identifier, not the mail value) stays the account name, even without an identifier.
a_v2, _ = _app(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False)
a_v2.ldap = _LDAP3({"bob@corp.example": {"id": "", "email": "b.mail@corp.example", "name": "Bob"}})
new_v2 = a_v2._check_ldap("bob@corp.example", "x")
r.check("… a UPN that is not the mail value signs in as before the fix (no regression)",
        new_v2 is not None and new_v2["username"] == "bob@corp.example" and not new_v2["email"], str(new_v2))

# V3: forward auth blocks only what the cleaning really removes; start finding for existing data.
a_v3, _ = _app()
_zwnj = a_v3.store.create_user("علی‌رضا", None, None, False, [], False)
_c0 = a_v3.store.create_user("boss\x01", None, None, False, [], False)
try:
    _head_v3 = a_v3._forward_response_headers(a_v3.get_user(_zwnj))
except _HTTPEx:
    _head_v3 = None
r.check("Counter-check R3/V3: an existing name with ZWNJ gets its remote user (does not collide)",
        _head_v3 is not None and "‌".encode("utf-8").decode("latin-1") in _head_v3["Remote-User"])
_trap_v3 = []
_h_v3 = _log3.Handler()
_h_v3.emit = lambda rec: _trap_v3.append(rec.getMessage())
_log3.getLogger("tinysesam.security").addHandler(_h_v3)
try:
    TinySesam(TinySesamConfig(db_path=a_v3.cfg.db_path, cookie_secure=False, base_url="http://testserver"))
finally:
    _log3.getLogger("tinysesam.security").removeHandler(_h_v3)
r.check("… and the startup names existing names with control/format characters",
        any("account name(s) with control or format characters" in m and str(_c0) in m for m in _trap_v3))
# The named route (since self-service) works: renamed, then the remote user is back.
_new_v3 = a_v3.change_username(_c0, "boss-new")
r.check("… and the route it names (auth.change_username) cleans the name up",
        any("auth.change_username" in m for m in _trap_v3) and _new_v3 == "boss-new"
        and a_v3._forward_response_headers(a_v3.get_user(_c0))["Remote-User"] == "boss-new")

# V4: SAML identifier with edge control characters hits no foreign binding.
a_v4, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", saml_email_trusted=True)
real_v4 = a_v4._check_saml("boss", {})
foreign_v4 = a_v4._check_saml("boss ", {})
r.check("Counter-check R3/V4: NameID `boss` + U+2028 does not end up in the account of the bound `boss`",
        real_v4 is not None and foreign_v4 is None, f"{real_v4 and real_v4['id']} / {foreign_v4}")

# V5: SAML not trusted, the name comes from the address attribute itself (even without "@").
a_v5, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", saml_attr_username="email")
manager_v5 = a_v5.create_user("boss", password=PW, is_admin=True)
new_v5 = a_v5._check_saml("opaque-mallory", {"email": ["boss"]})
r.check("Counter-check R3/V5: SAML name from the address attribute (`boss`) does not bind the local account",
        new_v5 is not None and new_v5["id"] != manager_v5 and new_v5["username"].startswith("saml-")
        and a_v5.store.get_federated_identifier("saml", manager_v5) is None, str(new_v5))

# I2: client newly created at the provider (different client_id) — no no, the row goes.
a_i2, _, _ = _oidc_with_refresh("i2-account")
_uid_i2 = a_i2.store.get_user_by_name("i2-account")["id"]
a_i2.store._exec("UPDATE oidc_session SET client_id='old-client-id', checked_at = checked_at - 16 * 60")
a_i2.oidc.refresh = lambda rt, sub: ("rejected", {}, {"error": "invalid_grant"})
a_i2._oidc_recheck(a_i2.store._one("SELECT * FROM session"))
a_i2._oidc_outcome.wait()
r.check("Counter-check R3/I2: token of an old client_id → row discarded, session stays, no no",
        a_i2.store._one("SELECT COUNT(*) AS n FROM oidc_session")["n"] == 0
        and a_i2.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 1
        and (a_i2.store.get_user(_uid_i2)["idp_confirmed_at"] or 0) > 0)

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
u_i4 = a_i4.create_user("pk-lost", password=PW, email="pkv@example.com")
a_i4.store.add_webauthn(u_i4, b"cred-i4", b"pub", 0, "[]", "Altes Handy")
a_i4.grant_mfa_enrollment(u_i4, 60)
c_i4, _ = _link_login(a_i4, ap_i4, "pk-lost")
r.check("Counter-check R3/I4: a window opened by the operator wins (lost device, link only)",
        c_i4.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False).status_code == 200)

# I5: if the session gets a new token during the exchange, the rotated refresh token is not lost.
a_i5, _, _ = _oidc_with_refresh("i5-account")
_old_i5 = a_i5.store._one("SELECT token_hash FROM session")["token_hash"]


def _swap_with_rotation(rt, sub):
    # In the middle of the exchange: step-up or similar gives the session a new token, the OIDC row follows.
    a_i5.store._exec("UPDATE session SET token_hash='new-i5' WHERE token_hash=?", (_old_i5,))
    a_i5.store._exec("UPDATE oidc_session SET token_hash='new-i5' WHERE token_hash=?", (_old_i5,))
    return "ok", {"sub": sub}, {"refresh_token": "rt-rotated"}


a_i5.oidc.refresh = _swap_with_rotation
a_i5.store._exec("PRAGMA foreign_keys=OFF")
a_i5.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60")
a_i5._oidc_recheck(a_i5.store._one("SELECT * FROM session"))
a_i5._oidc_outcome.wait()
_z_i5 = a_i5.store._one("SELECT refresh FROM oidc_session WHERE token_hash='new-i5'")
r.check("Counter-check R3/I5: rotation during the exchange — the new refresh token lands on the row",
        _z_i5 is not None and a_i5.store.vault.decrypt(_z_i5["refresh"]) == "rt-rotated")
# (Mutation probes: LDAP back on "@" instead of the mail value → V1 red, V2 red; forward latch back to
#  name_invalid → V3 red; start finding removed → V3b red; trim the identifier → V4 red; client_id comparison
#  removed → I2 red; "not magic" instead of "passkey" → I3 red; window check removed → I4 red;
#  old_encrypted removed → I5 red.)

# ── Upper limit without successful re-check (PO decision 2026-09-25: 25 hours) ───────────────
a_ob, _, c_ob = _oidc_with_refresh("ob-account")
_uid_ob = a_ob.store.get_user_by_name("ob-account")["id"]
r.check("Upper limit: default 25 hours, state of the row set at login",
        a_ob.cfg.oidc_session_max_unverified_hours == 25
        and a_ob.store._one("SELECT success_at FROM oidc_session")["success_at"] is not None)
a_ob.oidc.refresh = lambda rt, sub: ("ok", {"sub": sub}, {})
_prior_ob = int(_when.time()) - 2 * 3600
a_ob.store._exec("UPDATE oidc_session SET checked_at = checked_at - 16 * 60, success_at = ?", (_prior_ob,))
c_ob.get("/auth/me")
a_ob._oidc_outcome.wait()
r.check("… a yes at the exchange resets the state",
        (a_ob.store._one("SELECT success_at FROM oidc_session")["success_at"] or 0) > _prior_ob)
a_ob.oidc.refresh = lambda rt, sub: ("error", {}, {"error": "invalid_client"})
a_ob.store._exec("UPDATE oidc_session SET success_at = ?", (int(_when.time()) - 24 * 3600,))
r.check("… 24 hours without a yes: the session stays", c_ob.get("/auth/me").status_code == 200)
a_ob.store._exec("UPDATE oidc_session SET success_at = ?", (int(_when.time()) - 26 * 3600,))
_reply_ob = c_ob.get("/auth/me").status_code
r.check("… 26 hours without a yes: the session ends, with an audit row — and that is NOT a no for the keys",
        _reply_ob == 401 and a_ob.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0
        and a_ob.store._one("SELECT 1 FROM audit WHERE event='oidc_unconfirmed'") is not None
        and (a_ob.store.get_user(_uid_ob)["idp_confirmed_at"] or 0) > 0, f"HTTP {_reply_ob}")
a_ob0, _, c_ob0 = _oidc_with_refresh("ob-aus", oidc_session_max_unverified_hours=0)
a_ob0.store._exec("UPDATE oidc_session SET success_at = 1000")
r.check("… oidc_session_max_unverified_hours=0 switches the limit off", c_ob0.get("/auth/me").status_code == 200)
# (Mutation probes: remove the check in `_oidc_recheck` → "26 hours" red; `success=True`
#  at the exchange removed → "a yes resets the state" red; `_idp_no` instead of just deleting → keys check
#  red.)

# ── Schema 11, intermediate state: `failure_series` without column `art` is recreated (R2-3) ────────
_path_z = str(Path(tempfile.mkdtemp()) / "between.db")
Store(_path_z).db.close()
_raw = sqlite3.connect(_path_z)
_raw.execute("DROP TABLE failure_series")
_raw.execute("CREATE TABLE failure_series (folded TEXT PRIMARY KEY, count INTEGER NOT NULL, "
             "since INTEGER NOT NULL, last_seen INTEGER NOT NULL)")
_raw.commit()
_raw.close()
_z = Store(_path_z)
_columns = {z["name"] for z in _z._all("PRAGMA table_info(failure_series)")}
r.check("Intermediate state: a `failure_series` without `art` is recreated instead of breaking every sign-in",
        "kind" in _columns and _z.increase_failure_series("x", "password") == 1, str(_columns))
_z.db.close()

# ── Schema 11: a file from 0.20.x gets the table at startup ───────────────────────────────
_path = str(Path(tempfile.mkdtemp()) / "alt.db")
Store(_path).db.close()
_raw = sqlite3.connect(_path)
_raw.execute("DROP TABLE failure_series")
_raw.execute("PRAGMA user_version = 10")
_raw.commit()
_raw.close()
_new = Store(_path)
_tables = {z["name"] for z in _new._all("SELECT name FROM sqlite_master WHERE type='table'")}
r.check("Schema 10 → today: `failure_series` is created at startup, the stamp follows",
        "failure_series" in _tables
        and int(_new.db.execute("PRAGMA user_version").fetchone()[0]) == Store.SCHEMA_VERSION >= 11)
_new.db.close()
os.remove(_path)

sys.exit(r.done())
