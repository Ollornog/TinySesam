"""Pending pre-bookings (G9): the first window of an LDAP outage no longer locks anyone out.

The login route books every attempt IN ADVANCE as a failed attempt (R7-2) and withdraws it when the
directory is down (F-23) — but only once the outage has been reported. For a directory
that drops packets, that is after the timeout. After the first outage the `FailureMarker`
keeps it short; the FIRST window remained: whoever knocked during those seconds saw the hanging
pre-bookings as failed attempts — 429 for the colleagues behind the same NAT address and for the
emergency admin with the correct password, plus `failed login … reason=lockout_ip` for fail2ban and a
"Locked sign-in" mail to bystanders. Afterwards not a single failed attempt was in the table.

Now the pre-booking is pending in the database (`login_attempt.offen`). Whoever would fail only on pending
pre-bookings waits until they are decided — bounded in time and number. The
burst (R7-2) stays throttled: it waits along and then gets the real lockout.

The deadlines are shortened in the test (`_PENDING_DEADLINE_SEC`); the directory hangs for `HANGS` seconds.
"""
from __future__ import annotations

import io
import logging
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.ldap_ import DirectoryNotReachable  # noqa: E402
from tinysesam.security import seclog  # noqa: E402
from tinysesam.store import Store, now  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Pending pre-bookings — the first window of an LDAP outage (G9)")
HANGS = 1.5
DEADLINE = 4.0
PW = "Notfall-Pw-15!"
NAT = ("198.51.100.7", 40000)


class Directory:
    """A moody directory: hangs until the "timeout", rejects quickly, or raises."""

    def __init__(self, mode="haengt", duration=HANGS):
        self.mode = mode
        self.duration = duration
        self.questions = 0
        self._counter = threading.Lock()

    def authenticate(self, username, password):
        with self._counter:
            self.questions += 1
        if self.mode == "haengt":
            time.sleep(self.duration)
            raise DirectoryNotReachable("LDAP-Verzeichnis ldap://dummy nicht benutzbar: timed out")
        if self.mode == "weg":
            raise DirectoryNotReachable("LDAP-Verzeichnis ldap://dummy nicht benutzbar: Test")
        if self.mode == "kaputt":
            raise RuntimeError("unexpected error in the client")
        time.sleep(self.duration)
        if self.mode == "richtig":
            return {"username": username, "email": None, "name": username, "groups": [], "id": f"l-{username}"}
        return None                                    # „falsch“: password rejected


def wait_until(condition, was, deadline=20.0):
    """Wait until `condition()` is true — instead of a fixed time (T-18).

    Until 2026-10-07 these places had `time.sleep(HANGS * 0.4)` in the hope that the
    parallel sign-ins had arrived in the hanging directory by then. Under load that once was not
    enough (CI job repeat, PR #108): the precondition was read before all were there. Now
    it is read as soon as they are there; if the state does not come, that is a named error."""
    end = time.monotonic() + deadline
    while not condition():
        if time.monotonic() > end:
            raise AssertionError(f"Timeout ({deadline} s): {was}")
        time.sleep(0.01)


def _setup(directory, **hardening):
    db = str(Path(tempfile.mkdtemp()) / "t.db")
    auth = TinySesam(TinySesamConfig(db_path=db, cookie_secure=False, csrf_enabled=False,
                                     passkey_enabled=False, oidc_enabled=False, lang="de",
                                     ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
                                     base_url="http://testserver"))
    post: list = []
    auth.set_mailer(lambda to, subject, text, html=None: post.append((to, subject)))
    auth.set_security("rate_limit_max", 1000)          # a 429 must come from the lockout
    for k, v in hardening.items():
        auth.set_security(k, v)
    auth._PENDING_DEADLINE_SEC = DEADLINE
    auth.create_user("admin", password=PW, email="admin@example.com")
    auth.create_user("alice", email="alice@example.com")     # directory account without a local password
    auth.ldap = directory
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, post, db


def _sign_in(app, name, pw="x", client=NAT, when=None):
    t0 = time.monotonic()
    response = TestClient(app, client=client, raise_server_exceptions=False).post(
        "/auth/login", data={"username": name, "password": pw}, follow_redirects=False)
    if when is not None:
        when.append(time.monotonic() - t0)
    return response.status_code


def _failregex(file):
    text = (ROOT / "deploy" / "fail2ban" / file).read_text(encoding="utf-8")
    line = [z for z in text.splitlines() if z.startswith("failregex =")][0]
    return re.compile(line.split("=", 1)[1].strip().replace("<HOST>", r"(?P<host>\S+)"))


class Recording:
    """The security log in the format of the shipped file, without timestamp (like fail2ban)."""

    def __enter__(self):
        self.buffer = io.StringIO()
        self.check = logging.StreamHandler(self.buffer)
        self.check.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        seclog.addHandler(self.check)
        return self

    def __exit__(self, *_):
        seclog.removeHandler(self.check)

    def lines(self, word=""):
        return [z for z in self.buffer.getvalue().splitlines() if word in z]


def _old_unclosed(auth, name, ip, count):
    """Open pre-bookings that nobody completed (process died) — older than the deadline."""
    old = now() - Store.PREBOOKING_PENDING_SEC - 1
    for _ in range(count):
        auth.store._exec("INSERT INTO login_attempt(ts, username, ip, success, method, offen) "
                         "VALUES (?,?,?,0,'password',1)", (old, name, ip))


# ── (a) The first window: nobody gets locked out, the emergency admin gets in ─────────────────
dir_a = Directory("haengt")
auth, app, post, db = _setup(dir_a)
pair = auth._sec("max_login_attempts")
threshold_ip = pair * auth._sec("ip_attempt_factor")
with Recording() as log_a, ThreadPoolExecutor(max_workers=threshold_ip + 4) as pool:
    # Impatient Alice clicks five times, the office behind the same NAT address signs in.
    running = [pool.submit(_sign_in, app, "alice") for _ in range(pair)]
    running += [pool.submit(_sign_in, app, f"kollege{i}") for i in range(threshold_ip - pair)]
    wait_until(lambda: dir_a.questions >= threshold_ip, f"{threshold_ip} attempts in the hanging directory")
    pending = auth.store.count_fails(0, ip=NAT[0])
    confirmed = auth.store.count_fails(0, ip=NAT[0], only_confirmed=True)
    when_admin: list = []
    alice6 = pool.submit(_sign_in, app, "alice")
    admin = pool.submit(_sign_in, app, "admin", PW, NAT, when_admin)
    alice6, admin = alice6.result(timeout=30), admin.result(timeout=30)
    hanging = [f.result(timeout=30) for f in running]
auth._notice_outcome.wait()
r.check("precondition: in the first window as many pre-bookings are pending as the IP threshold",
        pending == threshold_ip and confirmed == 0, f"{pending} counted, {confirmed} confirmed")
r.check("precondition: the admin waited (the lockout would have applied)",
        when_admin and when_admin[0] >= HANGS * 0.3, f"{when_admin}")
r.check("the emergency admin gets in with the correct password (303, not 429)", admin == 303, f"{admin}")
r.check("Alice's sixth click gets the outage (503), no lockout", alice6 == 503, f"{alice6}")
r.check("the hanging attempts end with 503", set(hanging) == {503}, f"{sorted(set(hanging))}")
r.check("no `failed login` in the security log (fail2ban does not ban the NAT address)",
        not log_a.lines("failed login"), "; ".join(log_a.lines("failed login"))[:300])
r.check("no “Gesperrte Anmeldung” mail to bystanders", post == [], f"{post}")
r.check("afterwards no failed attempt of the address is in the table",
        auth.store.count_fails(0, ip=NAT[0]) == 0, f"{auth.store.count_fails(0, ip=NAT[0])}")
os.remove(db)

# ── (b) R7-2 stays: a burst waits along and then gets the real lockout ─────────────────────────
# The directory rejects quickly. Exactly `max_login_attempts` attempts reach it; the rest waits
# for their outcome (or, with no waiting slot, immediately gets the deferral) and then runs into the lockout.
dir_b = Directory("falsch", duration=0.3)
auth, app, post, db = _setup(dir_b)
pair = auth._sec("max_login_attempts")
with Recording() as log_b, ThreadPoolExecutor(max_workers=3 * pair) as pool:
    volley = list(pool.map(lambda i: _sign_in(app, "alice", f"falsch{i}"), range(3 * pair)))
auth._notice_outcome.wait()
r.check("R7-2: exactly max_login_attempts attempts reach the directory",
        dir_b.questions == pair, f"{dir_b.questions} of {3 * pair}")
r.check("R7-2: the rest get 429", sorted(volley) == [401] * pair + [429] * (2 * pair), f"{sorted(volley)}")
r.check("R7-2: the lockout appears with `reason=lockout_user` in the security log",
        any("failed login user=alice" in z and "reason=lockout_user" in z for z in log_b.lines()),
        "; ".join(log_b.lines())[:400])
r.check("R7-2: the real failed attempts appear in it as `failed login … method=password`",
        len([z for z in log_b.lines("failed login user=alice") if "method=password" in z]) == pair)
r.check("R7-2: after the burst nothing is open any more",
        auth.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE offen=1")["n"] == 0)
os.remove(db)

# ── (c) An open pre-booking that nobody completes becomes a failed attempt after the deadline ──
auth, app, post, db = _setup(Directory("falsch", duration=0))
_old_unclosed(auth, "alice", NAT[0], auth._sec("max_login_attempts"))
when_c: list = []
with Recording() as log_c:
    status_c = _sign_in(app, "alice", when=when_c)
r.check("orphaned pre-bookings: immediate lockout (429), no waiting",
        status_c == 429 and when_c[0] < DEADLINE / 2, f"{status_c} after {when_c[0]:.1f} s")
r.check("orphaned pre-bookings: `reason=lockout_user` in the log, no deferral",
        any("reason=lockout_user" in z for z in log_c.lines("failed login"))
        and not log_c.lines("deferred"), "; ".join(log_c.lines())[:300])
os.remove(db)

# The same for the series (B2-6): an old open pre-booking counts there too.
auth, app, post, db = _setup(Directory("falsch", duration=0), max_login_attempts=100)
limit_s = auth._sec("account_max_consecutive_failures")
_old_unclosed(auth, "alice", "192.0.2.50", limit_s)
for _ in range(limit_s):
    auth.store.increase_failure_series("alice")
when_c2: list = []
with Recording() as log_c2:
    status_c2 = _sign_in(app, "alice", when=when_c2)
r.check("orphaned pre-bookings in the series: immediate `lockout_series`, no deferral",
        status_c2 == 429 and when_c2[0] < DEADLINE / 2
        and any("reason=lockout_series" in z for z in log_c2.lines("failed login"))
        and not log_c2.lines("deferred"), f"{status_c2} after {when_c2[0]:.1f} s; {log_c2.lines()}"[:400])
os.remove(db)

# If a rule already applies with the confirmed rows, it takes precedence — no waiting for another one
# that only applies while pending. Here five pre-bookings of Alice are pending (another process is checking
# them right now), and the address has already reached its threshold with confirmed failed attempts.
auth, app, post, db = _setup(Directory("falsch", duration=0))
for _ in range(auth._sec("max_login_attempts")):
    auth.store._exec("INSERT INTO login_attempt(ts, username, ip, success, method, offen) "
                     "VALUES (?,'alice',?,0,'password',1)", (now(), NAT[0]))
for i in range(auth._sec("max_login_attempts") * auth._sec("ip_attempt_factor")):
    auth.store.record_attempt(f"kollege{i}", NAT[0], False, "password")
when_c3: list = []
with Recording() as log_c3:
    status_c3 = _sign_in(app, "alice", when=when_c3)
r.check("a rule that applies with confirmed rows takes precedence over the pending one: `lockout_ip` immediately",
        status_c3 == 429 and when_c3[0] < DEADLINE / 2
        and any("reason=lockout_ip" in z for z in log_c3.lines("failed login"))
        and not log_c3.lines("deferred"), f"{status_c3} after {when_c3[0]:.1f} s; {log_c3.lines()}"[:400])
os.remove(db)

# ── (d) The series: a hanging pre-booking at the limit does not trigger a series lockout ──────
dir_d = Directory("haengt")
auth, app, post, db = _setup(dir_d, max_login_attempts=100)
limit_s = auth._sec("account_max_consecutive_failures")
for _ in range(limit_s - 1):
    auth.store.increase_failure_series("alice")
with Recording() as log_d, ThreadPoolExecutor(max_workers=2) as pool:
    hanging_d = pool.submit(_sign_in, app, "alice", "x", ("192.0.2.60", 40000))
    wait_until(lambda: dir_d.questions >= 1, "the hanging attempt in the directory")
    state_d = (auth.store.failure_series("alice"), auth.store.failure_series_confirmed("alice"))
    parallel_d = pool.submit(_sign_in, app, "alice", "y", ("192.0.2.61", 40000)).result(timeout=30)
    hanging_d = hanging_d.result(timeout=30)
auth._notice_outcome.wait()
r.check("precondition: the series is at the limit with the hanging pre-booking",
        state_d == (limit_s, limit_s - 1), f"{state_d}")
r.check("parallel login at the limit: outage (503), no series lockout",
        parallel_d == 503 and hanging_d == 503, f"{parallel_d}, {hanging_d}")
r.check("parallel login at the limit: no `lockout_series`, no lockout mail",
        not any("lockout_series" in z for z in log_d.lines()) and post == [], f"{log_d.lines()} {post}"[:300])
r.check("…and the series is afterwards back at limit−1", auth.store.failure_series("alice") == limit_s - 1,
        f"{auth.store.failure_series('alice')}")
os.remove(db)

# Without a waiting slot at the same spot: the deferral does not show the text of the series lockout ("until you
# reset your password"), and `is_locked` reports it as a deferral — without `lockout_series`, without mail.
dir_d3 = Directory("haengt")
auth, app, post, db = _setup(dir_d3, max_login_attempts=100)
auth._pending_places = threading.BoundedSemaphore(1)
auth._pending_places.acquire()                          # all waiting slots taken
for _ in range(limit_s - 1):
    auth.store.increase_failure_series("alice")
with Recording() as log_d3, ThreadPoolExecutor(max_workers=1) as pool:
    hanging_d3 = pool.submit(_sign_in, app, "alice", "x", ("192.0.2.60", 40000))
    wait_until(lambda: dir_d3.questions >= 1, "the hanging attempt in the directory")
    page_html_d3 = TestClient(app, client=("192.0.2.61", 40000)).post(
        "/auth/login", data={"username": "alice", "password": "y"}, follow_redirects=False)
    locked_d3 = auth._is_locked("alice", "192.0.2.62")
    hanging_d3.result(timeout=30)
auth._notice_outcome.wait()
r.check("deferral at the series limit: 429 with the text of the window lockout, not of the series lockout",
        page_html_d3.status_code == 429 and auth.t("err.locked") in page_html_d3.text
        and "in Folge" not in page_html_d3.text and "in Folge" in auth.t("err.locked_series"),
        f"{page_html_d3.status_code}")
r.check("is_locked at the series limit with pending pre-booking: True, as deferral",
        locked_d3 and len(log_d3.lines("deferred login")) == 2
        and not any("lockout_series" in z for z in log_d3.lines()) and post == [],
        f"{locked_d3} {log_d3.lines()} {post}"[:400])
os.remove(db)

# Withdrawal and completion lower the series in the SAME transaction as the row. Separately, the
# pre-booking stood in between as neither open nor withdrawn, and whoever was waiting read
# the series one too high — at the limit a lockout including a lockout mail for nothing.
dir_t = Directory("weg")
auth, app, post, db = _setup(dir_t)
calls: list = []
_real = auth.store._series_minus


def _spy(bucket, kind):
    calls.append((bucket, kind, auth.store.db.in_transaction))
    return _real(bucket, kind)


auth.store._series_minus = _spy
_sign_in(app, "alice")                                  # failure → withdrawal
dir_t.mode, dir_t.duration = "richtig", 0
auth._ldap_failure = type(auth._ldap_failure)()          # the marker is armed after the failure
status_t = _sign_in(app, "alice")                       # success → completion
r.check("withdrawal and success lower the series in the row's transaction",
        calls == [("alice", "password", True), ("alice", "password", True)] and status_t == 303,
        f"{calls}, {status_t}")
r.check("…and the series is afterwards at 0", auth.store.failure_series("alice") == 0, f"{auth.store.failure_series('alice')}")
os.remove(db)

# ── (e) Waiting slots: whoever gets none immediately gets the deferral — without a lockout ────
dir_e = Directory("haengt")
auth, app, post, db = _setup(dir_e, max_login_attempts=1)
auth._pending_places = threading.BoundedSemaphore(1)
times_e: list = []
with Recording() as log_e, ThreadPoolExecutor(max_workers=3) as pool:
    hanging_e = pool.submit(_sign_in, app, "alice")
    wait_until(lambda: dir_e.questions >= 1, "the hanging attempt holds the single waiting slot")
    waiting = [pool.submit(_sign_in, app, "alice", "x", NAT, times_e) for _ in range(2)]
    status_e = sorted(f.result(timeout=30) for f in waiting)
    hanging_e.result(timeout=30)
auth._notice_outcome.wait()
times_e.sort()
r.check("without waiting slot: immediately 429, the other waits and gets the outage (503)",
        status_e == [429, 503] and times_e[0] < HANGS * 0.4 <= times_e[1],
        f"{status_e}, Zeiten {[round(z, 2) for z in times_e]}")
deferred = log_e.lines("deferred login")
r.check("without waiting slot: `deferred login … reason=pending` in the log, no `failed login`, no mail",
        len(deferred) == 1 and "user=alice" in deferred[0] and "reason=pending" in deferred[0]
        and not log_e.lines("failed login") and post == [], f"{log_e.lines()} {post}"[:400])
# Name and address come raw from the request: a line break in them must not produce a second line, otherwise
# an attacker writes a forged `failed login` line with a foreign IP that fail2ban counts (CodeQL #266).
with Recording() as log_e2:
    auth._deferred("alice\nWARNING failed login user=x ip=198.51.100.7", "203.0.113.9\r\nip=198.51.100.8")
r.check("deferral with a line break in name and address: exactly one line, no forged `failed login`",
        len(log_e2.lines()) == 1 and not log_e2.lines("failed login\n")
        and log_e2.lines()[0].startswith("WARNING deferred login user=alice"), f"{log_e2.lines()}")

# ── (g) The shipped fail2ban filters do not match the deferral ─────────────────────────────────
jail, jail_check = _failregex("tinysesam-filter.conf"), _failregex("tinysesam-verify-filter.conf")
r.check("the failregex of both jails does not match `deferred login`",
        deferred and not any(j.search(z) for z in deferred for j in (jail, jail_check)), f"{deferred}")
r.check("counter-check: the same line as `failed login` would hit the jail",
        deferred and bool(jail.search(deferred[0].replace("deferred login", "failed login")
                                      .replace(" reason=", " method=blocked reason="))))
os.remove(db)

# ── (h) is_locked: a deferral is True, but without a lockout mail and without `failed login` ──
dir_h = Directory("haengt")
auth, app, post, db = _setup(dir_h)
with Recording() as log_h, ThreadPoolExecutor(max_workers=auth._sec("max_login_attempts")) as pool:
    running = [pool.submit(_sign_in, app, "alice") for _ in range(auth._sec("max_login_attempts"))]
    wait_until(lambda: dir_h.questions >= auth._sec("max_login_attempts"), "all attempts in the hanging directory")
    locked_h = auth._is_locked("alice", NAT[0])
    [f.result(timeout=30) for f in running]
    free_h = not auth._is_locked("alice", NAT[0])
auth._notice_outcome.wait()
r.check("is_locked during pending pre-bookings: True, afterwards False", locked_h and free_h,
        f"{locked_h}, {free_h}")
r.check("is_locked on deferral: `deferred login`, no `failed login`, no mail",
        log_h.lines("deferred login") and not log_h.lines("failed login") and post == [],
        f"{log_h.lines()} {post}"[:300])
os.remove(db)

# ── (f) An unexpected exception leaves no pending row behind ───────────────────────────────────
auth, app, post, db = _setup(Directory("kaputt"))
status_f = _sign_in(app, "alice")
lines_f = [(z["offen"], z["success"]) for z in auth.store._all("SELECT offen, success FROM login_attempt")]
r.check("exception in the directory client: 500, the attempt is a confirmed failed attempt",
        status_f == 500 and lines_f == [(0, 0)], f"{status_f}, {lines_f}")
os.remove(db)

# ── (i) p2 F3: `lockout_series` exactly at the transition of the settled state ──────────────────
# Until 2026-09-27 a failed attempt logged the series state at ITS booking, including pending
# pre-bookings. The owner (correct password) and an attacker (wrong) are pending at the same time,
# the series is at limit−2: the owner is fully signed in and ends the series, the
# attacker fails with the booked state = limit — `lockout_series` in the audit log and "locked"
# in the security log, although nothing was locked.
CORRECT_I = "richtig-im-verz"


class Checking(Directory):
    """Accepts exactly one password, after `duration` seconds."""

    def authenticate(self, username, password):
        with self._counter:
            self.questions += 1
        time.sleep(self.duration)
        if password == CORRECT_I:
            return {"username": username, "email": None, "name": username, "groups": [], "id": f"l-{username}"}
        return None


def _series_lines(auth):
    return auth.store._one("SELECT COUNT(*) AS n FROM audit WHERE event='lockout_series'")["n"]


dir_i = Checking(duration=0.6)
auth, app, post, db = _setup(dir_i, max_login_attempts=1000, account_max_consecutive_failures=10)
limit_i = auth._sec("account_max_consecutive_failures")
for _ in range(limit_i - 2):
    auth.store.increase_failure_series("alice")
with Recording() as log_i, ThreadPoolExecutor(max_workers=2) as pool:
    holder = pool.submit(_sign_in, app, "alice", CORRECT_I, ("198.51.100.1", 40000))
    wait_until(lambda: dir_i.questions >= 1, "the owner in the directory")
    attacker = pool.submit(_sign_in, app, "alice", "falsch", ("203.0.113.66", 40000))
    holder, attacker = holder.result(timeout=30), attacker.result(timeout=30)
auth._notice_outcome.wait()
# (Mutation probe: in `record_login` restore `state = prebooked[2]` and `state == limit`, plus in
#  `reserve_attempt` the sum instead of the settled state → one row → red.)
r.check("p2 F3: owner and attacker are pending at limit−2, the owner ends the series — "
        "no `lockout_series` in the audit log, no “locked” in the security log",
        holder == 303 and attacker == 401 and auth.store.failure_series("alice") == 0
        and _series_lines(auth) == 0 and not log_i.lines("locked") and post == [],
        f"{holder}/{attacker}, Serie {auth.store.failure_series('alice')}, Zeilen {_series_lines(auth)}, "
        f"{log_i.lines('locked')} {post}"[:400])
os.remove(db)

# Counter-check: the real lockout by burst — exactly one row, with pending (LDAP) and without.
dir_i2 = Directory("falsch", duration=0.3)
auth, app, post, db = _setup(dir_i2, max_login_attempts=1000, account_max_consecutive_failures=10)
for _ in range(limit_i - 1):
    auth.store.increase_failure_series("alice")
with Recording() as log_i2, ThreadPoolExecutor(max_workers=6) as pool:
    volley_i2 = sorted(pool.map(lambda i: _sign_in(app, "alice", f"falsch{i}", (f"192.0.2.{20 + i}", 40000)),
                               range(6)))
auth._notice_outcome.wait()
r.check("p2 F3 counter-check with LDAP (pending): burst at limit−1 → one question to the directory, series "
        "stands, exactly one `lockout_series` row",
        dir_i2.questions == 1 and volley_i2 == [401] + [429] * 5
        and auth.store.failure_series_confirmed("alice") == limit_i and _series_lines(auth) == 1
        and len(log_i2.lines("locked: ")) == 1,
        f"{dir_i2.questions} {volley_i2} {auth.store.failure_series_confirmed('alice')} {_series_lines(auth)}")
os.remove(db)

db_i3 = str(Path(tempfile.mkdtemp()) / "t.db")
auth_i3 = TinySesam(TinySesamConfig(db_path=db_i3, cookie_secure=False, csrf_enabled=False,
                                    passkey_enabled=False, oidc_enabled=False, lang="de"))
for k, v in (("rate_limit_max", 1000), ("max_login_attempts", 1000), ("account_max_consecutive_failures", 10)):
    auth_i3.set_security(k, v)
auth_i3.create_user("bert", password=PW)
app_i3 = FastAPI()
app_i3.include_router(auth_i3.router())
for _ in range(limit_i - 1):
    auth_i3.store.increase_failure_series("bert")
with ThreadPoolExecutor(max_workers=6) as pool:
    volley_i3 = sorted(pool.map(lambda i: _sign_in(app_i3, "bert", f"falsch{i}", (f"192.0.2.{40 + i}", 40000)),
                               range(6)))
r.check("p2 F3 counter-check without LDAP (settled immediately): burst at limit−1 → exactly one `lockout_series` row",
        volley_i3 == [401] + [429] * 5 and _series_lines(auth_i3) == 1, f"{volley_i3} {_series_lines(auth_i3)}")
# Immediately settled booking over the limit, the series is ended before its completion (a full
# sign-in by another route): no row. And mixed — one pending and one immediately
# settled at the limit, completed in both orders: exactly one.
auth_i3.store.delete_failure_series("bert")
for _ in range(limit_i - 1):
    auth_i3.store.increase_failure_series("bert")
_prior_i3 = _series_lines(auth_i3)
_v = auth_i3._begin_attempt("bert", "192.0.2.60", "pin")
auth_i3.lift_lockout(auth_i3.store.get_user_by_name("bert")["id"])
auth_i3._record_login("bert", "192.0.2.60", False, "pin", attempt=_v)
# (Mutation probe: replace `min(prebooked[2], afterwards)` with `prebooked[2]` in `record_login` → red.)
r.check("p2 F3: booking over the limit, series ended before completion → no row",
        _v is not None and _series_lines(auth_i3) == _prior_i3, f"{_v} {_series_lines(auth_i3) - _prior_i3}")
_mixed = []
for order in ("schwebend zuerst", "feststehend zuerst"):
    auth_i3.store.delete_failure_series("bert")
    for _ in range(limit_i - 2):
        auth_i3.store.increase_failure_series("bert")
    _prior = _series_lines(auth_i3)
    _s = auth_i3._begin_attempt("bert", "192.0.2.61", "password", hover=True)
    _f = auth_i3._begin_attempt("bert", "192.0.2.62", "pin")
    for v, m in ((_s, "password"), (_f, "pin"))[::1 if order == "schwebend zuerst" else -1]:
        auth_i3._record_login("bert", "192.0.2.61", False, m, attempt=v)
    _mixed.append((order, _s is not None and _f is not None, _series_lines(auth_i3) - _prior))
# (Mutation probe: delete `before < max_series <= afterwards` → „schwebend zuerst" 0 rows → red.)
r.check("p2 F3: pending and immediately settled booking at the limit — exactly one row in both orders",
        all(ok_ and n == 1 for _, ok_, n in _mixed), str(_mixed))
auth_i3.store.db.close()
os.remove(db_i3)

# ── (j) p2 V1: an overall deadline for the question to the directory ───────────────────────────
# The pre-booking is pending for at most `Store.PREBOOKING_PENDING_SEC`; after that it counts as a failed attempt
# of a dead process. ldap3 only knows one deadline per response (10 s), and a search-then-bind
# with StartTLS waits up to ten times: a slow but responding directory let a still
# running sign-in count as a confirmed failed attempt. Measured with a substituted ldap3 and
# a clock that only the dummy presents — without real waiting time.
import types as _types  # noqa: E402

from tinysesam import ldap_ as _ldap_mod  # noqa: E402


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t


def _ldap3_slow(clock, response_sec, transcript):
    """ldap3 dummy: every response needs `response_sec`; if the deadline of the waiting point is shorter,
    it ends after the deadline with the error that ldap3 raises there."""
    mod = _types.ModuleType("ldap3")
    mod.NONE, mod.BASE = "NONE", "BASE"
    mod.AUTO_BIND_NO_TLS, mod.AUTO_BIND_TLS_BEFORE_BIND = "NO_TLS", "TLS_BEFORE_BIND"
    core = _types.ModuleType("ldap3.core")
    lx = _types.ModuleType("ldap3.core.exceptions")
    for name in ("LDAPException", "LDAPCommunicationError", "LDAPStartTLSError", "LDAPBindError",
                 "LDAPMaximumRetriesError", "LDAPSSLConfigurationError"):
        setattr(lx, name, type(name, (Exception,), {}))
    lx.LDAPSocketOpenError = type("LDAPSocketOpenError", (lx.LDAPCommunicationError,), {})
    lx.LDAPSocketReceiveError = type("LDAPSocketReceiveError", (lx.LDAPCommunicationError,), {})

    def wait(deadline, error):
        if response_sec >= deadline:
            clock.t += deadline
            raise error("timed out")
        clock.t += response_sec

    class Tls:
        def __init__(self, **kw):
            pass

    class Server:
        def __init__(self, url, **kw):
            self.url, self.connect_timeout = url, kw.get("connect_timeout")

    class Entry:
        entry_dn = "uid=alice,ou=people,dc=example,dc=com"

        def __contains__(self, name):
            return False

    class Connection:
        def __init__(self, server, **kw):
            self.server, self.deadline, self.entries = server, kw.get("receive_timeout"), []
            transcript.append((server.connect_timeout, self.deadline))
            if kw.get("auto_bind"):
                self.open()
                if kw["auto_bind"] == "TLS_BEFORE_BIND":
                    self.start_tls()
                self.bind()

        def open(self):
            wait(self.server.connect_timeout, lx.LDAPSocketOpenError)
            if self.server.url.startswith("ldaps://"):
                wait(self.deadline, lx.LDAPSocketReceiveError)       # TLS handshake

        def start_tls(self):
            wait(self.deadline, lx.LDAPSocketReceiveError)           # response to StartTLS
            wait(self.deadline, lx.LDAPSocketReceiveError)           # TLS handshake

        def bind(self):
            wait(self.deadline, lx.LDAPSocketReceiveError)
            return True

        def search(self, *a, **kw):
            wait(self.deadline, lx.LDAPSocketReceiveError)
            self.entries = [Entry()]
            return True

        def unbind(self):
            pass

    mod.Tls, mod.Server, mod.Connection = Tls, Server, Connection
    conv = _types.ModuleType("ldap3.utils.conv")
    conv.escape_filter_chars = lambda v, encoding=None: v
    dn = _types.ModuleType("ldap3.utils.dn")
    dn.escape_rdn = lambda v: v
    return {"ldap3": mod, "ldap3.core": core, "ldap3.core.exceptions": lx,
            "ldap3.utils": _types.ModuleType("ldap3.utils"), "ldap3.utils.conv": conv, "ldap3.utils.dn": dn}


_LDAP3_NAMES = ("ldap3", "ldap3.core", "ldap3.core.exceptions", "ldap3.utils", "ldap3.utils.conv",
                "ldap3.utils.dn")


def _slow_questions(response_sec, **cfg):
    """(outcome, elapsed seconds, deadlines per connection) of a sign-in against the dummy."""
    clock, transcript = _Clock(), []
    before = {n: sys.modules.get(n) for n in _LDAP3_NAMES}
    when_before = _ldap_mod.time
    reason = dict(db_path=":memory:", ldap_enabled=True, ldap_url="ldap://verzeichnis.example.com",
                 ldap_allow_plaintext=True, ldap_bind_dn="cn=svc,dc=example,dc=com", ldap_bind_password="svc",
                 ldap_user_base="ou=people,dc=example,dc=com")
    reason.update(cfg)
    try:
        sys.modules.update(_ldap3_slow(clock, response_sec, transcript))
        _ldap_mod.time = clock
        start = clock.t
        try:
            outcome = "angemeldet" if _ldap_mod.LDAPClient(TinySesamConfig(**reason)).authenticate("alice", "pw") \
                else "abgewiesen"
        except _ldap_mod.DirectoryNotReachable:
            outcome = "nicht erreichbar"
        return outcome, clock.t - start, transcript
    finally:
        _ldap_mod.time = when_before
        for n, m in before.items():
            if m is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = m


_cases_j = {"Search-then-Bind + StartTLS": dict(ldap_start_tls=True),
             "Search-then-Bind, ldaps://": dict(ldap_url="ldaps://verzeichnis.example.com"),
             "Search-then-Bind, ohne TLS": dict(),
             "Direkt-Bind + StartTLS": dict(ldap_start_tls=True, ldap_bind_dn="", ldap_bind_password="",
                                            ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com")}
_measurement_j = {(name, sec): _slow_questions(sec, **cfg)[:2]
              for name, cfg in _cases_j.items() for sec in (0.01, 1.2, 1.9, 2.9, 4.5, 9.5)}
_to_lang_j = {k: v for k, v in _measurement_j.items() if v[1] > _ldap_mod.TOTAL_DEADLINE_SEC}
# (Mutation probe: in `_Deadline.per_wait_point` always `CONNECTION_TIMEOUT` again → up to 95 s → red.)
r.check("p2 V1: every sign-in against a slow but responding directory ends within the "
        f"overall deadline ({_ldap_mod.TOTAL_DEADLINE_SEC} s) — signed in or “nicht erreichbar”, never “abgewiesen”",
        not _to_lang_j and all(a in ("angemeldet", "nicht erreichbar") for a, _ in _measurement_j.values()),
        f"too long: {_to_lang_j}; {[(k, v) for k, v in _measurement_j.items() if v[0] == 'abgewiesen']}")
r.check("… a fast directory notices nothing: signed in, the service account with the half, the "
        "user connection with the whole remaining deadline per response (at most 10 s)",
        all(_measurement_j[(n, 0.01)][0] == "angemeldet" for n in _cases_j)
        and _slow_questions(0.01)[2] == [(4, 4), (8, 8)], str(_slow_questions(0.01)[2]))
r.check("… and the overall deadline lies with room below the pending time of the pre-booking",
        _ldap_mod.TOTAL_DEADLINE_SEC + 5 <= Store.PREBOOKING_PENDING_SEC,
        f"{_ldap_mod.TOTAL_DEADLINE_SEC} / {Store.PREBOOKING_PENDING_SEC}")
_deadline_before = _ldap_mod.TOTAL_DEADLINE_SEC
try:
    _ldap_mod.TOTAL_DEADLINE_SEC = 5                    # not enough for one second per waiting point
    _tight_j = _slow_questions(0.01, ldap_start_tls=True)
finally:
    _ldap_mod.TOTAL_DEADLINE_SEC = _deadline_before
# (Mutationsprobe: `except DirectoryNotReachable: raise` in `authenticate` delete → „abgewiesen“,
#  a failed attempt for the slowness of the directory → red.)
r.check("p2 V1: if the deadline is not enough, the directory counts as unreachable before it is asked "
        "(no failed attempt)", _tight_j[0] == "nicht erreichbar" and _tight_j[2] == [], str(_tight_j))

# ── Without LDAP nothing is pending, and the column also lands in a file that already carries schema 11 ─
db_o = str(Path(tempfile.mkdtemp()) / "t.db")
auth_o = TinySesam(TinySesamConfig(db_path=db_o, cookie_secure=False, csrf_enabled=False,
                                   passkey_enabled=False, oidc_enabled=False, lang="de"))
auth_o.create_user("bert", password=PW)
app_o = FastAPI()
app_o.include_router(auth_o.router())
_sign_in(app_o, "bert", "falsch")
r.check("without LDAP: the failed attempt is confirmed immediately (offen=0)",
        [z["offen"] for z in auth_o.store._all("SELECT offen FROM login_attempt")] == [0])
auth_o.store.db.close()
raw = sqlite3.connect(db_o)
raw.execute("ALTER TABLE login_attempt DROP COLUMN offen")
stamp = raw.execute("PRAGMA user_version").fetchone()[0]
raw.close()
auth_o = TinySesam(TinySesamConfig(db_path=db_o, cookie_secure=False, passkey_enabled=False, oidc_enabled=False))
columns = {z["name"] for z in auth_o.store._all("PRAGMA table_info(login_attempt)")}
r.check("a file from schema 11 without the column gets it at start (idempotent)",
        stamp == Store.SCHEMA_VERSION >= 11 and "offen" in columns
        and auth_o.store.count_fails(0, username="bert", only_confirmed=True) == 1, f"{stamp} {columns}")
auth_o.store.db.close()
os.remove(db_o)

sys.exit(r.done())
