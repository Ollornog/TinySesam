"""Hardening: brute-force lockout (per user), attempt tracking, audit log, panel settings."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, trusted_proxies=["127.0.0.1/32"]))
auth.ensure_admin("admin", "dummy123")

# Tighten hardening (as in the admin panel) and check persistence
auth.set_security("max_login_attempts", 3)
assert auth._sec("max_login_attempts") == 3

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)

# 3 failed attempts → locked afterwards, even with the CORRECT password
for i in range(3):
    assert c.post("/auth/login", data={"username": "admin", "password": f"wrong-{i}"}).status_code == 401, i
r = c.post("/auth/login", data={"username": "admin", "password": "dummy123"})
assert r.status_code == 429, f"after lockout 429 expected, was {r.status_code}"
print("  ✓ lockout after 3 failed attempts (blocks the correct password too)")

fails = [a for a in auth.store.recent_audit(20) if a["event"] == "login_fail"]
assert len(fails) >= 3
print(f"  ✓ audit log: {len(fails)}× login_fail")

# Unlock (admin) → login possible again + login audit
auth.store.clear_fails(username="admin")
r = c.post("/auth/login", data={"username": "admin", "password": "dummy123"}, follow_redirects=False)
assert r.status_code == 303
assert any(a["event"] == "login" for a in auth.store.recent_audit(5))
print("  ✓ login OK after unlocking + login audit")

# Settings round trip (editable in the panel)
auth.set_security("rate_limit_max", 99)
assert auth._sec("rate_limit_max") == 99 and auth.all_security()["rate_limit_max"] == 99
print("  ✓ hardening settings persistent + readable via all_security()")

# Trusted proxy: XFF only from a trusted peer
from tinysesam import security
class Req:  # minimal fake
    def __init__(self, host, xff=None):
        self.client = type("C", (), {"host": host})()
        self.headers = {"x-forwarded-for": xff} if xff else {}
assert security.client_ip(Req("127.0.0.1", "9.9.9.9"), ["127.0.0.1/32"]) == "9.9.9.9"      # trusted proxy → XFF applies
assert security.client_ip(Req("8.8.8.8", "9.9.9.9"), ["127.0.0.1/32"]) == "8.8.8.8"        # untrusted peer → XFF ignored
print("  ✓ real client IP: XFF only behind a trusted proxy")

# ---------- R4-10: /auth/password is no password oracle ----------
# Attack: the old-password check of this route ran without rate_ok/is_locked/record_login AND
# resolved the account via the login identifier (`check_password(u["username"], …)` → find_user)
# instead of via the ID of the own session. Whoever owns an account named "chef@example.com"
# while the account "chef" carries exactly this email guessed the password of the FOREIGN account
# unlimited and silently — no 429, no failed attempt, no log entry, and a hit
# silently set the own password (so the attack stayed invisible even on success).
AT = chr(64)          # no address in plain text in the source
def _mail(local): return local + AT + "example.com"

db2 = os.path.join(tempfile.mkdtemp(), "t.db")
auth2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, passkey_enabled=False,
                                  oidc_enabled=False, cookie_secure=False))
auth2.set_security("max_login_attempts", 3)
# The password change has its OWN counter with its own threshold — tightened here as well,
# so the test keeps both buckets apart (and does not measure the default 5 along).
auth2.set_security("password_change_max_attempts", 3)
# The throttle is measured further up; in this block a 429 is meant to PROVABLY come from the lock
# and not from the token bucket, otherwise (d) below would prove the opposite of what
# it states (all requests come from the same test IP).
auth2.set_security("rate_limit_max", 500)
app2 = FastAPI()
app2.include_router(auth2.router())
VICTIM_PW = "Victim-Password-2026"
GIVEN_PW = "Attacker-Password-1x"
uid_victim = auth2.create_user("chef", VICTIM_PW, email=_mail("chef"), is_admin=True)
# The collision arises via a raw INSERT, i.e. past the guard — it thereby represents a
# database from BEFORE R4-12 (legacy data). Since R4-12 `create_user` locks the two
# namespaces crosswise, a new collision can no longer arise via the API; an
# existing one is not resolved retroactively, though — the ID check here protects against exactly that.
# Since G12c `store.create_user` rejects it too (identifier trigger); an INSERT without a bucket is
# the route of a foreign writer (older version, sqlite3 tool) that the trigger does not see.
from tinysesam.store import now as _now                                     # noqa: E402
uid_given = auth2.store._exec("INSERT INTO users(username, display_name, email, created_at) "
                            "VALUES (?,?,?,?)", (_mail("chef"), _mail("chef"), _mail("eve"),
                                                 _now())).lastrowid
auth2.set_password(uid_given, GIVEN_PW)

# Precondition: the attacker's identifier really points to the foreign account. Without it
# the attack would come to nothing and the test would prove nothing.
assert auth2.find_user(_mail("chef"))["id"] == uid_victim != uid_given, "attack situation not established"

given = TestClient(app2)
tok, _ = auth2.start_session(uid_given, "password", remember=True)
given.cookies.set(auth2.cfg.session_cookie, tok)

# (a) The victim's CORRECT password is no longer a hit for this session.
r = given.post("/auth/password", json={"current": VICTIM_PW, "new": "new-long-passwordxxxx"})
assert r.status_code == 403, f"foreign password was accepted: {r.status_code}"
assert auth2._check_password("chef", VICTIM_PW) is not None, "victim's password was changed"
print("  ✓ /auth/password checks the own account ID, not the resolved login identifier")

# (b) Guessing is throttled: after password_change_max_attempts at the latest a 429 comes instead of a 403.
auth2.store.clear_fails(username=_mail("chef"))
LIMIT = auth2._sec("password_change_max_attempts")
codes = [given.post("/auth/password", json={"current": f"wrong{i}", "new": "new-long-passwordxxxx"}).status_code
         for i in range(LIMIT + 2)]
assert 429 in codes, f"no lockout on /auth/password: {codes}"
# The threshold is wired, not just present: the first 429 sits EXACTLY behind it.
# (Mutation probe: `limit = self.sec("password_change_max_attempts") - 1` in
# `is_password_change_locked` → [403, 403, 429, 429, 429]. `429 in codes` still holds, this
# line falls — which is why it is here.)
assert codes.index(429) == LIMIT, f"429 not after {LIMIT} failed attempts: {codes}"
assert auth2.store.count_fails(0, username=_mail("chef"), method="password_change") >= LIMIT, \
    "failed attempts were not booked"
assert any(a["event"] == "login_fail" and "password_change" in (a["detail"] or "")
           for a in auth2.store.recent_audit(20)), "no log entry for the failed attempt"
print("  ✓ old-password guessing runs into lock + log (429, login_attempt, audit log)")

# (c) The legitimate route keeps working — with the OWN password.
auth2.store.clear_fails(username=_mail("chef"))
r = given.post("/auth/password", json={"current": GIVEN_PW, "new": "new-long-passwordxxxx"})
assert r.status_code == 200, f"own password change fails: {r.status_code} {r.text[:120]}"
assert auth2._verify_user_password(uid_given, "new-long-passwordxxxx"), "new password not set"
assert auth2._check_password("chef", VICTIM_PW) is not None, "foreign account touched"
print("  ✓ own password change still possible unchanged")

# (d) Regression: the counter is METHOD-BOUND. Failed attempts at the password change are no
# sign-in attempt and must not lock the login. With the shared bucket three
# typos on the own account page locked the sign-in for `lockout_window_sec` — and without
# a way out: the password change was shut then too, and a success only clears the failed attempts
# of the SAME method. (Mutation probe: remove `exclude_methods` in `is_locked` → both
# following lines fall, `is_locked` True and login 429.)
ANNA_PW = "Anna-Password-2026"
uid_anna = auth2.create_user("anna", ANNA_PW)
anna = TestClient(app2)
tok_anna, _ = auth2.start_session(uid_anna, "password", remember=True)
anna.cookies.set(auth2.cfg.session_cookie, tok_anna)
for i in range(LIMIT + 1):
    anna.post("/auth/password", json={"current": f"mistyped{i}", "new": "new-long-passwordxxxx"})
assert auth2.store.count_fails(0, username="anna", method="password_change") >= LIMIT, \
    "typos were not booked — the test measures nothing"
assert not auth2._is_locked("anna", "testclient"), "typos at the password change lock the login"
fresh = TestClient(app2)
r = fresh.post("/auth/login", data={"username": "anna", "password": ANNA_PW}, follow_redirects=False)
assert r.status_code == 303, f"login locked after typos at the password change: {r.status_code}"
assert auth2.cfg.session_cookie in fresh.cookies, "no session after the login"
print("  ✓ typos at the password change do not lock the sign-in (own counter)")

# (e) The lock still applies — where guessing happened: Anna's password change stays shut, even
# with the CORRECT old password. It can be lifted (admin route, like `python -m tinysesam unlock`).
r = anna.post("/auth/password", json={"current": ANNA_PW, "new": "new-long-passwordxxxx"})
assert r.status_code == 429, f"lock at the password change does not apply: {r.status_code}"
auth2.store.clear_fails(username="anna")
r = anna.post("/auth/password", json={"current": ANNA_PW, "new": "new-long-passwordxxxx"})
assert r.status_code == 200, f"password change after unlocking fails: {r.status_code} {r.text[:120]}"
print("  ✓ lock applies at the password change itself and can be lifted")

# (f) Regression, NAT amplification: the IP threshold of the login
# (`max_login_attempts * ip_attempt_factor`) also counted method-blind. That sufficed for
# several mistyping colleagues behind the same connection to lock the login of a completely UNINVOLVED fourth.
# The failed attempts here all come from the same test IP — exactly the
# situation of an office behind NAT. (Mutation probe: remove `exclude_methods` in the IP branch of `is_locked`
# → `is_locked("unbeteiligt", …)` becomes True and the third party's login 429.)
IP_LIMIT = auth2._sec("max_login_attempts") * auth2._sec("ip_attempt_factor")
assert auth2.store.count_fails(0, ip="testclient", method="password_change") == 0, \
    "precondition: the test IP starts without failed attempts at the password change"
for n in range(1, 9):
    if auth2.store.count_fails(0, ip="testclient", method="password_change") >= IP_LIMIT:
        break
    uid = auth2.create_user(f"colleague{n}", "Colleagues-Password-1")
    colleague = TestClient(app2)
    t, _ = auth2.start_session(uid, "password", remember=True)
    colleague.cookies.set(auth2.cfg.session_cookie, t)
    for _ in range(LIMIT):
        colleague.post("/auth/password", json={"current": "mistyped", "new": "new-long-passwordxxxx"})
# The IP threshold of the LOGIN is reached — with the method-blind counter every
# login from this IP would be locked from here on, even that of an account that never did anything wrong.
assert auth2.store.count_fails(0, ip="testclient", method="password_change") >= IP_LIMIT, \
    "attack situation not established: the test IP has not reached the login IP threshold"
auth2.create_user("uninvolved", "Third-Password-1x")
assert not auth2._is_locked("uninvolved", "testclient"), \
    "mistyping colleagues behind NAT lock out an uninvolved user"
third = TestClient(app2)
r = third.post("/auth/login", data={"username": "uninvolved", "password": "Third-Password-1x"},
                 follow_redirects=False)
assert r.status_code == 303, f"login of the uninvolved user locked: {r.status_code}"
print("  ✓ no NAT amplification: mistyping colleagues do not lock out uninvolved users")

# (g) Follow-up to the second round: the own bucket initially carried the IP dimension too
# (`limit * ip_attempt_factor`). Three mistyping colleagues thereby locked the fourth's
# OWN password change — the same collateral lock, just one level deeper, and against one
# who entered nothing wrong. On `main` this lock did not exist at all. It is not missing
# either: whoever guesses here already needs a valid session of THIS account.
# (Mutation probe: give `ip_faktor=self.sec("ip_attempt_factor")` back to `is_password_change_locked`
# → these three lines fall, the fourth gets 429.)
assert auth2.store.count_fails(0, ip="testclient", method="password_change") >= IP_LIMIT, \
    "precondition: the test IP has long exceeded the login IP threshold"
uid_fourth = auth2.create_user("fourth", "Fourth-Password-1")
fourth = TestClient(app2)
t4, _ = auth2.start_session(uid_fourth, "password", remember=True)
fourth.cookies.set(auth2.cfg.session_cookie, t4)
assert not auth2._is_password_change_locked("fourth", "testclient"), \
    "mistyping colleagues lock the uninvolved user's own password change"
r = fourth.post("/auth/password", json={"current": "Fourth-Password-1", "new": "new-long-passwordxxxx"})
assert r.status_code == 200, f"password change of the uninvolved user locked: {r.status_code} {r.text[:120]}"
print("  ✓ the own bucket locks per account, not per connection (no NAT collateral)")

# ---------- R4-10/round 2: the exception list is complete — and every exception has a brake ----------
# The first attempt only took `password_change` out of the login lockout. `record_login()` is
# called in the router with `reauth` (step-up confirmation) and `resource` (area PIN without account)
# as well, though: five typos at the reauth page locked the sign-in of the same account, and
# three areas with five missteps each reached the login IP threshold via `ip_attempt_factor` and
# locked the sign-in of completely unrelated accounts. Nobody noticed because no test held the CONTENT
# of the list against reality. That is exactly what the following three checks do.
import ast                                                                      # noqa: E402
from pathlib import Path                                                        # noqa: E402
from tinysesam import security as _sec                                          # noqa: E402

SOURCES = sorted((Path(__file__).resolve().parent.parent / "tinysesam").glob("*.py"))
REAL_SIGN_IN = {"password", "pin", "totp"}     # deliberately maintained here, not derived


def _record_login_methods(path: Path) -> set:
    """With which methods does this module source call `record_login()`? (AST, not grep:
    a docstring quoting the line is no call.)"""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "_record_login":
            continue
        arg = node.args[3] if len(node.args) > 3 else None
        for kw in node.keywords:
            if kw.arg == "method":
                arg = kw.value
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            found.add(arg.value)
        else:
            found.add(f"<non-constant in {path.name}:{node.lineno}>")
    return found


used = set().union(*(_record_login_methods(q) for q in SOURCES))
assert "password" in used and "reauth" in used and "resource" in used, \
    f"the collector no longer finds the known call sites: {sorted(used)}"
unknown = used - REAL_SIGN_IN - set(_sec.NOT_LOGIN_METHODS)
assert not unknown, (f"new record_login method(s) {sorted(unknown)}: either a real "
                       "sign-in attempt (then add to REAL_SIGN_IN above) or none "
                       "(then to security.OWN_LOCK — with an own bucket)")
print(f"  ✓ every record_login method is classified ({len(used)} found, AST over tinysesam/)")

# No entry without a brake: taking a method out of the login lockout without giving it an
# own bucket would mean making it guessable without limit.
db3 = os.path.join(tempfile.mkdtemp(), "t.db")
auth3 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db3, cookie_secure=False,
                                  passkey_enabled=False, oidc_enabled=False))
for _m in _sec.NOT_LOGIN_METHODS:
    bolt = getattr(auth3, _sec.OWN_LOCK[_m], None)
    assert callable(bolt), f"{_m} is in NOT_LOGIN_METHODS but has no bucket of its own"
    name = f"probant-{_m}"
    for _ in range(20):
        auth3._record_login(name, "198.51.100.4", False, _m)
    assert not auth3._is_locked(name, "198.51.100.4"), \
        f"failed attempts with method={_m} lock the sign-in (neither sign-in nor exception?)"
    assert bolt(name, "198.51.100.4"), \
        f"method={_m} is taken out of the login lockout, but {_sec.OWN_LOCK[_m]} does not brake"
print(f"  ✓ every non-login method has a brake of its own ({', '.join(_sec.NOT_LOGIN_METHODS)})")

# And the buckets are separate: one does not fill the other.
for _m in _sec.NOT_LOGIN_METHODS:
    for _other in _sec.NOT_LOGIN_METHODS:
        if _other == _m:
            continue
        assert not getattr(auth3, _sec.OWN_LOCK[_other])(f"probant-{_m}", None), \
            f"failed attempts with method={_m} lock {_other} too"
print("  ✓ the buckets are sealed against each other (a misstep of one method does not lock the other)")
os.remove(db3)


# ---------- T-13: locks atomic (R7-2, R3-2, R3-7) ----------
# The whole check lay between `is_locked()` and `record_login()`. A parallel volley read
# N times "not locked yet" and was allowed to guess N times. The probe artificially slows the check
# (otherwise chance wins) and sends twelve requests at once: no more than the limit may
# get through to the check. (Mutation probe: in `login_password` again
# `is_locked()` + `record_login()` without `attempt` → all twelve get through.)
import threading                                                                # noqa: E402
import time as _time                                                            # noqa: E402
from concurrent.futures import ThreadPoolExecutor                               # noqa: E402
import pyotp                                                                    # noqa: E402


def _volley(count, call):
    """Release `anzahl` calls at once (barrier), return status codes."""
    start = threading.Barrier(count)

    def one(i):
        start.wait(timeout=10)
        return call(i)
    with ThreadPoolExecutor(max_workers=count) as pool:
        return sorted(pool.map(one, range(count)))


def _slow(obj, name, sec=0.25):
    real = getattr(obj, name)

    def brake(*a, **k):
        _time.sleep(sec)
        return real(*a, **k)
    setattr(obj, name, brake)


db_t = os.path.join(tempfile.mkdtemp(), "t.db")
auth_t = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_t, cookie_secure=False,
                                   passkey_enabled=False, oidc_enabled=False, pin_enabled=True,
                                   pin_login=True))
auth_t.set_security("max_login_attempts", 3)
auth_t.set_security("pin_max_attempts", 3)
auth_t.set_security("rate_limit_max", 1000)
uid_t = auth_t.create_user("toni", "Toni-Password-2026")
auth_t.set_pin(uid_t, "13579")
app_t = FastAPI()
app_t.include_router(auth_t.router())

# (1) Password login (R7-2)
_slow(auth_t, "_check_password")
codes = _volley(12, lambda i: TestClient(app_t).post(
    "/auth/login", data={"username": "toni", "password": f"wrong{i}"}).status_code)
assert codes.count(401) <= 3, f"R7-2: {codes.count(401)} of 12 parallel attempts were allowed to guess: {codes}"
assert codes.count(429) >= 9, codes
print(f"  ✓ R7-2: parallel volley at the login — {codes.count(401)} checked, {codes.count(429)} locked")
auth_t.store.clear_fails(username="toni")

# (1b) Counting and booking are ONE step, not merely close together: here the
# counting itself is slowed. Whoever counts and books separately afterwards lets the volley through again.
# (Mutation probe: `begin_attempt` counts via `count_fails` and then books with its own
# INSERT → red.)
del auth_t._check_password                         # the real check again
_slow(auth_t.store, "_fails_query", 0.05)
# New passwords, not those of volley (1): one already tried counts only once since 0.24.9.
codes = _volley(12, lambda i: TestClient(app_t).post(
    "/auth/login", data={"username": "toni", "password": f"different{i}"}).status_code)
assert codes.count(401) <= 3, f"counting and booking are separate steps: {codes.count(401)} of 12 through"
del auth_t.store._fails_query
print(f"  ✓ …counting and booking in one transaction ({codes.count(401)} checked, {codes.count(429)} locked)")
auth_t.store.clear_fails(username="toni")

# (2) PIN login (R3-7) — the short key space is the actual target
_slow(auth_t, "_check_pin")
codes = _volley(12, lambda i: TestClient(app_t).post(
    "/auth/pin", data={"username": "toni", "pin": f"{i:04d}"}).status_code)
assert codes.count(401) <= 3, f"R3-7: {codes.count(401)} of 12 parallel PIN attempts were allowed to guess: {codes}"
print(f"  ✓ R3-7: parallel volley at the PIN — {codes.count(401)} checked, {codes.count(429)} locked")
auth_t.store.clear_fails(username="toni")

# (3) TOTP step (R3-2) — with known password, same half session for all
secret_text_t = auth_t.totp_begin(uid_t)["secret"]
auth_t.totp_confirm(uid_t, pyotp.TOTP(secret_text_t).now())
c_t = TestClient(app_t)
assert c_t.post("/auth/login", data={"username": "toni", "password": "Toni-Password-2026"},
                follow_redirects=False).status_code == 303
half = c_t.cookies.get(auth_t.cfg.session_cookie)
_slow(auth_t, "_verify_totp")


def _totp(i):
    ci = TestClient(app_t)
    ci.cookies.set(auth_t.cfg.session_cookie, half)
    return ci.post("/auth/totp", data={"code": "000000"}).status_code


codes = _volley(12, _totp)
assert codes.count(401) <= 3, f"R3-2: {codes.count(401)} of 12 parallel TOTP attempts were allowed to guess: {codes}"
print(f"  ✓ R3-2: parallel volley at the TOTP step — {codes.count(401)} checked, {codes.count(429)} locked")

# (4) Confirmation of the TOTP setup (B2-12/R3-6). The check spot came from another branch
# and stayed with the pattern `is_totp_setup_locked()` → check → `record_login()` without attempt: 40 of
# 40 parallel codes reached the check, with a limit of 5. The effect is small (whoever sets up
# sees the secret), but the promised limit only held for well-behaved single requests.
# (Mutation probe: in `totp_setup_confirm` again `is_totp_setup_locked()` + `record_login()`
# without `attempt` → 12 of 12 get through → red.)
auth_t.set_security("totp_setup_max_attempts", 3)
uid_tilda = auth_t.create_user("tilda", "Tilda-Password-2026")
c_tilda = TestClient(app_t)
assert c_tilda.post("/auth/login", data={"username": "tilda", "password": "Tilda-Password-2026"},
                    follow_redirects=False).status_code == 303
session_tilda = c_tilda.cookies.get(auth_t.cfg.session_cookie)
auth_t.totp_begin(uid_tilda)
_slow(auth_t, "totp_confirm")


def _set_up(i):
    ci = TestClient(app_t)
    ci.cookies.set(auth_t.cfg.session_cookie, session_tilda)
    return ci.post("/auth/totp/setup", data={"code": "000000"}).status_code


codes = _volley(12, _set_up)
checked = codes.count(200)
assert checked <= 3, f"B2-12: {checked} of 12 parallel setup codes were allowed to guess: {codes}"
assert codes.count(429) >= 9, codes
assert auth_t.store.count_fails(0, username="tilda", method="totp_setup") == checked, \
    "every checked code appears exactly once as a failed attempt in the own bucket"
del auth_t.totp_confirm
print(f"  ✓ B2-12: parallel volley at the TOTP setup — {checked} checked, {codes.count(429)} locked")
os.remove(db_t)

# ---------- R7-6 / H-8: account AND address, not account alone ----------
# Until T-13 five failed attempts from ANYWHERE locked the account for everyone — anyone who knew
# a username locked out its owner for a window, correct password included.
# Now the first threshold stops the pair of account and address; the account alone only closes at
# `account_attempt_factor` times that, i.e. only when several connections guess.
# (Mutation probe: remove the pair rule in `_rules` and set `lockout_account` to
# `max_login_attempts` → the owner gets 429.)
db_f = os.path.join(tempfile.mkdtemp(), "t.db")
auth_f = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_f, cookie_secure=False,
                                   passkey_enabled=False, oidc_enabled=False))
auth_f.create_user("holder", "Holder-Password-1x")
app_f = FastAPI()
app_f.include_router(auth_f.router())
G = auth_f._sec("max_login_attempts")
foreign = TestClient(app_f, client=("198.51.100.20", 40000))
codes = [foreign.post("/auth/login", data={"username": "holder", "password": f"rate-{_i}"}).status_code
         for _i in range(G + 1)]
assert codes == [401] * G + [429], codes
assert foreign.post("/auth/login", data={"username": "holder", "password": "Holder-Password-1x"}
                  ).status_code == 429, "the stranger's address is not locked for this account"
holder = TestClient(app_f, client=("203.0.113.21", 40000))
r = holder.post("/auth/login", data={"username": "holder", "password": "Holder-Password-1x"},
                 follow_redirects=False)
assert r.status_code == 303, f"R7-6: a stranger locks out the owner: {r.status_code}"
print("  ✓ R7-6/H-8: a stranger locks only the account+address pair, not the owner")
holder.get("/auth/logout")
# The account threshold stays against distributed guessing: many connections together lock the account.
# (The login above was complete and cleared the failed attempts — R7-1 —, so count anew.)
for i in range(auth_f._sec("account_attempt_factor")):
    ci = TestClient(app_f, client=(f"198.51.100.{30 + i}", 40000))
    for _j in range(G):
        ci.post("/auth/login", data={"username": "holder", "password": f"rate-{i}-{_j}"})
r = holder.post("/auth/login", data={"username": "holder", "password": "Holder-Password-1x"})
assert r.status_code == 429, f"distributed guessing across many addresses stays unlimited: {r.status_code}"
print("  ✓ …the account threshold still applies when many addresses guess together")
os.remove(db_f)

# The account threshold counts under the identifier that `find_user` reads — not under the raw text.
# Until the third round ' opfer', 'OPFER\t', '\xa0opfer' … hit the same account, but filled
# a bucket of their own each: an address pool with one spelling per address guessed without limit, and
# the probe above did not see it because it only typed the canonical identifier. (Mutation probe: in
# `TinySesam._bucket` return the raw `username` → 60 attempts reach the check.)
db_v = os.path.join(tempfile.mkdtemp(), "t.db")
auth_v = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_v, cookie_secure=False,
                                   passkey_enabled=False, oidc_enabled=False))
auth_v.create_user("victim", "Victim-Password-1", email="victim@example.com")
app_v = FastAPI()
app_v.include_router(auth_v.router())
G = auth_v._sec("max_login_attempts")
LID = G * auth_v._sec("account_attempt_factor")
variants = [" victim", "victim ", "\tvictim", "VICTIM", " Victim\t", "\xa0victim", "victim\n", "  vIcTiM  ",
             "\nVICTIM", "victim ", " victim ", "Victim"]
assert all(auth_v.find_user(v) for v in variants), "the variants no longer hit the same account"
checked = 0
for i, v in enumerate(variants):
    ci = TestClient(app_v, client=(f"2001:db8:1::{i:x}", 40000))
    for _j in range(G):
        checked += ci.post("/auth/login", data={"username": v, "password": f"rate-{i}-{_j}"}).status_code == 401
assert checked <= LID, \
    f"R7-6/H-8: {checked} attempts via spellings of the identifier, at most {LID} are promised"
r = TestClient(app_v, client=("203.0.113.22", 40000)).post(
    "/auth/login", data={"username": "victim", "password": "Victim-Password-1"})
assert r.status_code == 429, f"the account threshold did not apply at {checked} attempts: {r.status_code}"
print(f"  ✓ …also across whitespace and spellings of the identifier: {checked} checked, then closed")
# Lifting must hit the same bucket: the failed attempts stand under 'victim', not under '  vIcTiM  '.
assert auth_v.lift_lockout(auth_v.find_user("victim")["id"]) == checked
assert auth_v.store.count_fails(0, username="victim") == 0
os.remove(db_v)

# ---------- R7-1: the lockout counts method-blind — so a full sign-in clears the same way ----------
# Password, PIN and TOTP fill the same bucket; until T-13 a success only cleared its own
# method. Whoever got in COMPLETELY by PIN after two mistyped passwords carried the two
# along. A partial success (password before a TOTP step) still clears ONLY itself
# — otherwise the second factor would be guessable again. (Mutation probe: remove `lift_lockout` in
# `start_session` → the first promise falls.)
db_m = os.path.join(tempfile.mkdtemp(), "t.db")
auth_m = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_m, cookie_secure=False,
                                   passkey_enabled=False, oidc_enabled=False, pin_enabled=True,
                                   pin_login=True))
uid_m = auth_m.create_user("mia", "Mia-Password-2026")
auth_m.set_pin(uid_m, "24680")
app_m = FastAPI()
app_m.include_router(auth_m.router())
c_m = TestClient(app_m)
for _ in range(2):
    c_m.post("/auth/login", data={"username": "mia", "password": "mistyped"})
auth_m._record_login("mia", "testclient", False, "password_change")   # own bucket, stays
assert c_m.post("/auth/pin", data={"username": "mia", "pin": "24680"},
                follow_redirects=False).status_code == 303
assert auth_m.store.count_fails(0, username="mia", method="password") == 0, \
    "R7-1: a full sign-in leaves the failed attempts of the other methods standing"
assert auth_m.store.count_fails(0, username="mia", method="password_change") == 1, \
    "the full sign-in also clears the own buckets (account page) — that does not belong"
print("  ✓ R7-1: a full sign-in clears all sign-in buckets, not the own ones")
c_m.get("/auth/logout")
# Partial success: the password succeeds, TOTP is still pending → the TOTP failed attempts stay.
secret_text_m = auth_m.totp_begin(uid_m)["secret"]
auth_m.totp_confirm(uid_m, pyotp.TOTP(secret_text_m).now())
auth_m._record_login("mia", "testclient", False, "totp")
assert c_m.post("/auth/login", data={"username": "mia", "password": "Mia-Password-2026"},
                follow_redirects=False).status_code == 303
assert auth_m.store.count_fails(0, username="mia", method="totp") == 1, \
    "a half login clears the failed attempts of the second factor — TOTP becomes guessable again"
print("  ✓ …a half login (TOTP pending) does not clear the second factor")
os.remove(db_m)

os.remove(db2)

os.remove(db)
print("\nHARDENING OK ✅")
