"""The same wrong password counts only once (0.24.9, `password_repeat_memory`).

PO 2026-10-09: “typing the same password 10 times is hardly a hack attempt.” A phone with an old password
asks again and again in rhythm with the same value — until now it locked account and home IP after five tries, and fail2ban
banned the IP on top. Now:

  (a) ten times the same wrong password from the same IP: one failed attempt, nine times `repeated login`, no lockout,
      the correct password gets through afterwards, the response stays the same 401 every time
  (b) six DIFFERENT wrong passwords lock as before (counter-check)
  (c) the same repetition from another IP counts there once anew
  (d) `password_repeat_memory=0` switches it off — then the repetition locks as before
  (e) only N fingerprints are remembered: whoever sends N+1 passwords in a circle counts every time
  (f) security log: `WARNING failed login` only for the first, `INFO repeated login` afterwards, `INFO login ok` on
      success — and only the first line hits the shipped failregex
  (g) no password is in memory, only 8-byte fingerprints
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

PW = "Correct-Pw-2026xx"
OLD = "old-password-2025xx"
IP_A = ("203.0.113.9", 50000)
IP_B = ("198.51.100.4", 50000)


def ok(text):
    print(f"  ok   {text}")


def _app(**hardening):
    d = tempfile.mkdtemp()
    log = os.path.join(d, "security.log")
    auth = TinySesam(TinySesamConfig(db_path=os.path.join(d, "t.db"), cookie_secure=False, csrf_enabled=False,
                                     base_url="http://testserver", lang="de", passkey_enabled=False,
                                     security_log=log))
    for k, v in {"rate_limit_max": 100000, **hardening}.items():
        auth.set_security(k, v)
    auth.create_user("anna", PW)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, log


def _login(app, pw, ip=IP_A):
    return TestClient(app, client=ip).post("/auth/login", data={"username": "anna", "password": pw, "next": "/"},
                                           follow_redirects=False)


def _lines(log, word):
    with open(log, encoding="utf-8") as fh:
        return [z for z in fh.read().splitlines() if f" {word} " in z]


def _audit(auth, event):
    """`login_fail` = counted failed attempts, `login_repeat` = repetitions (audit `login_fail … reason=repeated`)."""
    all_items = [e for e in auth.store.recent_audit(limit=500) if e["event"] == "login_fail"]
    repeat = [e for e in all_items if "reason=repeated" in (e["detail"] or "")]
    return repeat if event == "login_repeat" else [e for e in all_items if e not in repeat]


print("Password-Repetitionxx")

# (a) + (f)
auth, app, log = _app()
responses = [_login(app, OLD) for _ in range(10)]
assert all(r.status_code == responses[0].status_code for r in responses), [r.status_code for r in responses]
assert responses[0].status_code in (200, 401), responses[0].status_code
assert len({re.sub(r"[A-Za-z0-9_-]{20,}", "", r.text) for r in responses}) == 1, "the response to a repetition differs from the first failed attempt"
ok("ten times the same wrong password: the same response every time (except for the nonce)")
assert len(_audit(auth, "login_fail")) == 1 and len(_audit(auth, "login_repeat")) == 9
ok("audit: ten times login_fail, nine of them with reason=repeated")
r = _login(app, PW)
assert r.status_code in (302, 303) and "set-cookie" in r.headers, (r.status_code, r.text[:200])
ok("afterwards the correct password gets through — no lockout (window 5)")
assert len(_lines(log, "failed login")) == 1 and len(_lines(log, "repeated login")) == 9
assert len(_lines(log, "login ok")) == 1, _lines(log, "login ok")
FAILREGEX = re.compile(r"^\s*WARNING failed login user=.* ip=(?P<host>\S+) method=\S+(?: reason=\S+)?$")
with open(ROOT / "deploy" / "fail2ban" / "tinysesam-filter.conf", encoding="utf-8") as fh:
    assert "WARNING failed login user=.* ip=<HOST>" in fh.read()
with open(log, encoding="utf-8") as fh:
    hit = [z for z in fh.read().splitlines() if FAILREGEX.match(z.split(" ", 2)[2])]
assert len(hit) == 1, hit
ok("security log: 1× failed login, 9× repeated login, 1× login ok — only the first hits the failregex")

# (g)
raw = repr(auth._pw_repetition)
assert OLD not in raw and PW not in raw
assert all(len(f) == 8 for items in auth._pw_repetition.values() for f, _ in items)
ok("8-byte fingerprints are in memory, no password")

# (b) Counter-check
auth, app, log = _app()
for i in range(6):
    _login(app, f"wrong-{i}-xxxxxxxx")
r = _login(app, PW)
assert not (r.status_code in (302, 303) and "set-cookie" in r.headers), r.status_code
ok("six different wrong passwords lock as before")

# (c) another IP counts anew, but also only once there
auth, app, log = _app()
for _ in range(3):
    _login(app, OLD, IP_A)
    _login(app, OLD, IP_B)
assert len(_audit(auth, "login_fail")) == 2 and len(_audit(auth, "login_repeat")) == 4
ok("once per IP: two failed attempts, four repetitions")

# (d) switched off
auth, app, log = _app(password_repeat_memory=0)
for _ in range(6):
    _login(app, OLD)
assert len(_audit(auth, "login_fail")) >= 5 and not _audit(auth, "login_repeat")
r = _login(app, PW)
assert not (r.status_code in (302, 303) and "set-cookie" in r.headers), r.status_code
ok("password_repeat_memory=0: every repetition counts, the lockout applies")

# (e) circle of N+1 passwords
auth, app, log = _app(password_repeat_memory=2, max_login_attempts=20)
for _ in range(2):
    for i in range(3):
        _login(app, f"circle-{i}-xxxxxxxx")
assert len(_audit(auth, "login_fail")) == 6 and not _audit(auth, "login_repeat"), (
    len(_audit(auth, "login_fail")), len(_audit(auth, "login_repeat")))
ok("three passwords in a circle with memory 2: each counts")

print("Password repetition OK")

# (h) `login ok … unban=yes|no` (0.24.10): yes only without failed attempts against OTHER accounts from the same IP
print("login ok: unban")


def _unban(log):
    z = _lines(log, "login ok")[-1]
    return z.rsplit("unban=", 1)[1]


auth, app, log = _app()
_login(app, PW)
assert _unban(log) == "yes", _lines(log, "login ok")
ok("without failed attempts: unban=yes")
for i in range(3):
    _login(app, f"mistyped-{i}-xxxxxxxx")
_login(app, PW)
assert _unban(log) == "yes"
ok("own typos before: unban=yes")
auth.create_user("bob", "Bobs-Password-2026")
for i in range(3):
    TestClient(app, client=IP_A).post("/auth/login", data={"username": "bob", "password": f"rate-{i}-xxxxxx"})
_login(app, PW)
assert _unban(log) == "no", _lines(log, "login ok")
ok("failed attempts against a foreign account from the same IP: unban=no")
_login(app, PW, IP_B)
assert _unban(log) == "yes"
ok("the same sign-in from another IP: unban=yes")
print("login ok: unban OK")
