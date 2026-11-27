"""T-98: an operator resets a lost authenticator app (TOTP) — in the panel and from the CLI.

The panel route `POST <admin>/api/users/{uid}/totp/reset` (`PanelActions.reset_totp`) and the CLI
`tinysesam reset-totp` remove the TOTP together with the recovery codes, end the TOTP share of the lockout and write
an audit line. The panel route is for administrators only, follows the owner model and wants a fresh confirmation.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import __main__ as cli  # noqa: E402
from tinysesam.messages import MESSAGES  # noqa: E402

BASE = "https://auth.example.com"
JSON = {"Accept": "application/json"}
ADMIN = "/auth/admin/api"
STALE = 100000


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False,
               base_url=BASE, totp_enabled=True, admin_require_mfa=False, stepup_max_age_sec=900)
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session_client(auth, app, uid, *, age=0):
    """A full password session for `uid` whose sign-in and last confirmation lie `age` seconds back."""
    c = TestClient(app)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    then = int(time.time()) - age
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def with_totp(auth, uid) -> int:
    """Give `uid` a confirmed TOTP, recovery codes and two failed TOTP guesses (plus one password guess)."""
    auth.store.set_totp(uid, pyotp.random_base32(), confirmed=True)
    codes = len(auth.generate_recovery_codes(uid))
    name = auth.store.get_user(uid)["username"]
    for method in ("totp", "totp", "password"):
        auth.store.record_attempt(name, "203.0.113.9", False, method)
    auth.store.increase_failure_series(name, kind="totp")
    auth.store.increase_failure_series(name, kind="password")
    return codes


def fails(auth, uid, method):
    return auth.store.count_fails(0, username=auth.store.get_user(uid)["username"], method=method)


def series(auth, uid, kind):
    return auth.store.failure_series_without(auth.store.get_user(uid)["username"],
                                             [k for k in ("password", "pin", "totp", "magic") if k != kind])


auth, app = build()
auth.ensure_admin("root", "root-pw-12345")                     # the first admin is the owner
root = auth.store.get_user_by_name("root")["id"]
helper = auth.create_user("helper", password="helper-pw-12345", is_admin=True)
vic = auth.create_user("vic", password="vic-pw-1234567")
plain = auth.create_user("plain", password="plain-pw-123456")
events = []
auth.on_security_event = lambda name, account, detail: events.append((name, account["username"]))
codes = with_totp(auth, vic)
assert auth.store.has_confirmed_totp(vic) and auth.recovery_codes_remaining(vic) == codes
assert fails(auth, vic, "totp") == 2 and fails(auth, vic, "password") == 1

# (a) the state the panel shows
fresh = session_client(auth, app, helper, age=5)
r = fresh.get(f"{ADMIN}/users/{vic}/totp", headers=JSON)
assert r.status_code == 200 and r.json() == {"enabled": True, "recovery_left": codes, "enrollment_until": None}, r.text
assert fresh.get(f"{ADMIN}/users/{plain}/totp", headers=JSON).json()["enabled"] is False
assert fresh.get(f"{ADMIN}/users/999999/totp", headers=JSON).status_code == 404
ok("the panel reads whether an account has a TOTP (and how many recovery codes are left)")

# (b) a stale admin session is refused, nothing removed
stale = session_client(auth, app, helper, age=STALE)
assert stale.get(f"{ADMIN}/users", headers=JSON).status_code == 200, "the panel itself stays open (no admin MFA)"
r = stale.post(f"{ADMIN}/users/{vic}/totp/reset", headers=JSON)
assert r.status_code == 403, (r.status_code, r.text[:200])
assert auth.store.has_confirmed_totp(vic) and auth.recovery_codes_remaining(vic) == codes
ok("a stale admin session gets 403 (step-up) and the TOTP stays")

# (c) not an administrator: 403, the account keeps its TOTP
member = session_client(auth, app, plain, age=5)
assert member.post(f"{ADMIN}/users/{vic}/totp/reset", headers=JSON).status_code == 403
assert member.get(f"{ADMIN}/users/{vic}/totp", headers=JSON).status_code == 403
assert auth.store.has_confirmed_totp(vic)
ok("an account without panel rights neither reads nor resets a TOTP")

# (d) the reset: TOTP and recovery codes gone, TOTP lockout ended (the password share stays), audit, event
r = fresh.post(f"{ADMIN}/users/{vic}/totp/reset", headers=JSON)
assert r.status_code == 200 and r.json() == {"ok": True, "recovery_codes_deleted": codes}, r.text
assert not auth.store.has_confirmed_totp(vic) and auth.recovery_codes_remaining(vic) == 0
assert fails(auth, vic, "totp") == 0 and fails(auth, vic, "password") == 1, "only the TOTP share of the lockout ends"
assert series(auth, vic, "totp") == 0 and series(auth, vic, "password") == 1
lines = {a["event"]: a for a in auth.store.recent_audit(50)}
assert lines["totp_reset_by_admin"]["username"] == "helper" and f"uid={vic}" in lines["totp_reset_by_admin"]["detail"]
assert lines["totp_disable"]["username"] == "vic", "the holder's own line, so `tinysesam audit --user vic` finds it"
assert ("totp_disabled", "vic") in events, events
ok("the reset removes TOTP and recovery codes, ends only the TOTP lockout, logs actor and holder, tells the holder")

# (e) nothing to reset: 409 with a text in both languages
r = fresh.post(f"{ADMIN}/users/{vic}/totp/reset", headers=JSON)
assert r.status_code == 409 and r.json()["detail"] == MESSAGES["en"]["api.no_totp"], r.text
assert fresh.post(f"{ADMIN}/users/999999/totp/reset", headers=JSON).status_code == 404
ok("an account without TOTP: 409 'no authenticator app'; an unknown account: 404")

# (f) owner model: only an owner resets an owner's TOTP
with_totp(auth, root)
assert fresh.post(f"{ADMIN}/users/{root}/totp/reset", headers=JSON).status_code == 403
assert auth.store.has_confirmed_totp(root)
owner = session_client(auth, app, root, age=5)
assert owner.post(f"{ADMIN}/users/{root}/totp/reset", headers=JSON).status_code == 200
assert not auth.store.has_confirmed_totp(root)
ok("an admin without owner role does not reset an owner's TOTP; an owner does")

# (g) the panel offers it: texts in both languages, the button wired to the route
for lang in ("en", "de"):
    for key in ("admin.totp", "admin.totp_on", "admin.totp_off", "admin.totp_reset", "admin.totp_hint",
                "admin.confirm.totp_reset", "api.no_totp"):
        assert MESSAGES[lang].get(key), (lang, key)
assert MESSAGES["de"]["admin.totp_reset"] != MESSAGES["en"]["admin.totp_reset"]
page = owner.get("/auth/admin", headers={"Accept": "text/html"}).text
assert "/totp/reset" in page and "totpreset" in page.split("const ACT=", 1)[1].split(";", 1)[0], \
    "the panel script calls the reset route and lists it among its actions"
ok("panel texts in English and German; the panel script wires the button to the route")

# (g2) T-130: the setup window — open it for a while, close it; a fresh confirmation to open, owner model, bounds
auth.cfg.mfa_enrollment = "strict"
assert not auth.mfa_enrollment_allowed(vic), "strict: an account that signed in before may not set up by itself"
assert stale.post(f"{ADMIN}/users/{vic}/mfa-enrollment", json={"minutes": 30}, headers=JSON).status_code == 403
assert not auth.mfa_enrollment_allowed(vic), "a stale admin session opens no window"
for bad in (0, 24 * 60 + 1, "60", True, None):
    assert fresh.post(f"{ADMIN}/users/{vic}/mfa-enrollment", json={"minutes": bad}, headers=JSON).status_code == 400, bad
before = int(time.time())
r = fresh.post(f"{ADMIN}/users/{vic}/mfa-enrollment", json={"minutes": 30}, headers=JSON)
assert r.status_code == 200 and before + 30 * 60 <= r.json()["until"] <= int(time.time()) + 30 * 60, r.text
assert auth.mfa_enrollment_allowed(vic)
state = fresh.get(f"{ADMIN}/users/{vic}/totp", headers=JSON).json()
assert state["enrollment_until"] == r.json()["until"] and state["enabled"] is False, state
assert fresh.post(f"{ADMIN}/users/{root}/mfa-enrollment", json={}, headers=JSON).status_code == 403, "owner model"
assert member.post(f"{ADMIN}/users/{vic}/mfa-enrollment/delete", headers=JSON).status_code == 403
assert stale.post(f"{ADMIN}/users/{vic}/mfa-enrollment/delete", headers=JSON).status_code == 200, "closing needs none"
assert not auth.mfa_enrollment_allowed(vic)
assert fresh.get(f"{ADMIN}/users/{vic}/totp", headers=JSON).json()["enrollment_until"] is None
events = [a["event"] for a in auth.store.recent_audit(80)]
assert "mfa_enrollment_granted_by_admin" in events and "mfa_enrollment_revoked_by_admin" in events, events
assert "totpwin" in page.split("const ACT=", 1)[1].split(";", 1)[0] and "/mfa-enrollment" in page
for lang in ("en", "de"):
    for key in ("admin.totp_window", "admin.totp_window_open", "admin.totp_window_close"):
        assert MESSAGES[lang].get(key), (lang, key)
auth.cfg.mfa_enrollment = "first_login"
ok("T-130: the panel opens the setup window (fresh confirmation, 1–1440 minutes, owner model) and closes it")

# (h) the CLI: the same reset without a running service
auth.close()
auth2, _ = build(db_path=auth.cfg.db_path)
codes = with_totp(auth2, vic)
db = auth2.cfg.db_path
auth2.close()
out, err = io.StringIO(), io.StringIO()
with redirect_stdout(out), redirect_stderr(err):
    rc = cli._reset_totp(["vic", "--db", db])
assert rc == 0 and f"{codes} recovery codes deleted" in out.getvalue(), (rc, out.getvalue(), err.getvalue())
auth3, _ = build(db_path=db)
assert not auth3.store.has_confirmed_totp(vic) and auth3.recovery_codes_remaining(vic) == 0
assert fails(auth3, vic, "totp") == 0 and fails(auth3, vic, "password") == 2
assert series(auth3, vic, "totp") == 0 and series(auth3, vic, "password") >= 1
line = next(a for a in auth3.store.recent_audit(50) if a["event"] == "totp_reset_cli")
assert line["username"] == "vic" and f"recovery_codes_deleted={codes}" in line["detail"], dict(line)
auth3.close()
ok("CLI reset-totp: TOTP and recovery codes gone, TOTP lockout ended, audit line totp_reset_cli")

out, err = io.StringIO(), io.StringIO()
with redirect_stdout(out), redirect_stderr(err):
    assert cli._reset_totp(["vic", "--db", db]) == 1
    assert cli._reset_totp(["nobody", "--db", db]) == 1
    assert cli._reset_totp(["vic", "--db", db + ".missing"]) == 1
assert "no authenticator app" in err.getvalue() and "No account 'nobody'" in err.getvalue(), err.getvalue()
assert not os.path.exists(db + ".missing"), "the CLI never creates a database"
ok("CLI: nothing to reset, unknown account, missing database → exit 1 with a reason")
print("OK test_totp_reset")
