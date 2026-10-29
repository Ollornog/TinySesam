"""Secure building blocks for custom step-up and password-change pages (0.22.0): `confirm_password`,
`confirm_pin`, `confirm_totp` and `change_password`.

PO decision 2026-09-27: after the login block (`login_*` → `LoginResult`, `test_sign_in.py`), the
same pattern for the confirmation before sensitive actions and for one's own password change. Until
then there were only the built-in routes `/auth/reauth` and `POST /auth/password`. Whoever built a
custom page reached for the inner verifiers (`verify_user_password`, `verify_user_pin`,
`verify_totp`), and those do not throttle: no lock, no counter, no line in the security log.
Now the built-in routes call the blocks (one source, no drift). Two things are measured:
that a custom page is protected via the block, and that it behaves line for
line like the built-in route.

  (a) custom step-up page: lock in its own bucket, throttle, success with freshness and a new token
  (b) no effect without a session, not even with a half one
  (c) an API key does not count (step-up and password change)
  (d) only offered methods; empty is not an attempt; PIN bucket (C-3); TOTP without a one-time code
  (e) custom password-change page: lock, password rule, the effect on success
  (f) CSRF (form field, header) and the result type `PasswordChangeResult`
  (g) equality with the built-in routes: status, text, audit, log and counter rows
  (h) one source: the routes call the block and no inner verifier (AST)
  (i) the README examples run verbatim and lock
  (j) the names: English, each one in tier A
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import io
import json
import logging
import re
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import pyotp  # noqa: E402
from fastapi import Depends, FastAPI, Form, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.concurrency import run_in_threadpool  # noqa: E402

from tinysesam import LoginResult, PasswordChangeResult, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.security import seclog  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Safe building blocks for custom step-up and password-change pages (confirm_*, change_password, 0.22.0)")
PW = "Confirmed-2026x"          # 15 characters
PW_NEW = "Whole-New-Pw15x"      # 15 characters
PIN = "4711"
IP = ("203.0.113.9", 50000)
LOOSE = {"max_login_attempts": 1000, "rate_limit_max": 100000, "account_max_consecutive_failures": 100000,
          "pin_max_attempts": 100, "reauth_max_attempts": 100, "password_change_max_attempts": 100}
JSON = {"accept": "application/json"}


def _app(hardening=None, **cfg):
    """TinySesam with built-in routes AND custom routes that only call the blocks."""
    reason = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, base_url="http://testserver", lang="de",
                 passkey_enabled=False, oidc_enabled=False)
    reason.update(cfg)
    auth = TinySesam(TinySesamConfig(**reason))
    for k, v in {**LOOSE, **(hardening or {})}.items():
        auth.set_security(k, v)
    app = FastAPI()
    app.include_router(auth.router())

    def response(erg):
        # The README pattern: on failure the custom form (JSON here) with the status of the
        # built-in page, on success the redirect with the renewed cookie.
        if not erg:
            return JSONResponse({"reason": erg.reason, "message": erg.message, "next_url": erg.next_url},
                                status_code=erg.status)
        return erg.redirect()

    @app.post("/own/confirm/{procedure}")
    def _own_confirm(procedure: str, request: Request, password: str = Form(""), pin: str = Form(""),
                       code: str = Form(""), next: str = Form(""), csrf: str = Form("", alias="_csrf")):
        if procedure == "password":
            return response(auth.confirm_password(request, password, next=next, csrf=csrf))
        if procedure == "pin":
            return response(auth.confirm_pin(request, pin, next=next, csrf=csrf))
        return response(auth.confirm_totp(request, code, next=next, csrf=csrf))

    @app.post("/own/confirm-json")
    def _own_confirm_json(request: Request, data: dict):
        # The JSON path: no `csrf` argument, the token comes in the X-CSRF-Token header.
        erg = auth.confirm_password(request, data.get("password", ""))
        response_ = JSONResponse({"reason": erg.reason, "done": erg.done}, status_code=200 if erg else erg.status)
        erg.set_cookie(response_)
        return response_

    @app.post("/own/password")
    def _own_password(request: Request, current: str = Form(""), new: str = Form(""),
                        csrf: str = Form("", alias="_csrf")):
        erg = auth.change_password(request, current, new, csrf=csrf)
        if not erg:
            return JSONResponse({"reason": erg.reason, "detail": erg.message}, status_code=erg.status)
        return {"ok": True, "api_keys_active": erg.api_keys_active}

    @app.post("/own/password-json")
    async def _own_password_json(request: Request):
        # `async def` like the built-in route: the check (argon2) runs in the thread pool, the
        # CSRF token (csrf=None) comes from the header.
        b = await request.json()
        erg = await run_in_threadpool(auth.change_password, request, b.get("current", ""), b.get("new", ""))
        return JSONResponse({"reason": erg.reason, "detail": erg.message}, status_code=erg.status)

    @app.get("/sensitive")
    def _sensitive(u=Depends(auth.require(mfa=True))):
        return {"u": u["username"]}

    return auth, app


def _client(app, ip=IP):
    return TestClient(app, client=ip)


def _sign_in(app, name, ip=IP, pw=PW):
    """A client with a full session — signed in via the built-in route."""
    c = _client(app, ip)
    a = c.post("/auth/login", data={"username": name, "password": pw, "next": "/"}, follow_redirects=False)
    assert a.status_code == 303, (name, a.status_code, a.text[:200])
    return c


def _stale(auth, c):
    """The session's last confirmation is long ago: `require(mfa=True)` does not let it through."""
    tok = c.cookies.get(auth.session_cookie_name)
    auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                     (int(time.time()) - 100000, auth.store.session_hash(tok)))


def _fresh(c):
    return c.get("/sensitive", headers=JSON, follow_redirects=False).status_code == 200


def _post(client, path, **data):
    return client.post(path, data={"next": "/sensitive", **data}, follow_redirects=False)


def _reason(response):
    try:
        return response.json().get("reason")
    except ValueError:
        return None


def _session(auth, response):
    return response.cookies.get(auth.session_cookie_name)


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


def _audit(auth):
    return [tuple(z) for z in auth.store._all("SELECT event, username, ip, detail FROM audit ORDER BY id")]


def _attempts(auth, method=None):
    lines = [tuple(z) for z in auth.store._all(
        "SELECT username, ip, success, method, pending FROM login_attempt ORDER BY id")]
    return [z for z in lines if method is None or z[3] == method]


def _sessions(auth, uid):
    return auth.store._all("SELECT token_hash FROM session WHERE user_id=?", (uid,))


def _totp_set_up(auth, uid):
    g = auth.totp_begin(uid)["secret"]
    auth.totp_confirm(uid, pyotp.TOTP(g).at(time.time() - 30))
    return g


# ── (a) Custom step-up page: lock, throttle, success ──────────────────────────────────────────
# Exactly the gap: a custom confirmation via `verify_user_password` would have said 401 five times here
# and made the session fresh on the sixth attempt. Via the block it locks after the limit
# (`reauth_max_attempts`), and even the correct password then makes nothing fresh any more.
# (Mutation probe: switch off the rejection `if attempt is None:` in `_confirm` → fourth
# response 401, the correct password 303 → red.)
auth, app = _app(hardening={"reauth_max_attempts": 3})
auth.create_user("alice", password=PW)
c = _sign_in(app, "alice")
_stale(auth, c)
with Recording() as log_a:
    sequence_a = [_post(c, "/own/confirm/password", password=f"wrong-{i}") for i in range(5)]
    correct_a = _post(c, "/own/confirm/password", password=PW)
r.check("(a) custom step-up page: after 3 failed attempts 429 `locked` (text of the page) — no further guessing",
        [a.status_code for a in sequence_a] == [401, 401, 401, 429, 429]
        and [_reason(a) for a in sequence_a] == ["invalid"] * 3 + ["locked"] * 2
        and sequence_a[0].json()["message"] == auth.t("err.reauth") and sequence_a[3].json()["message"] == auth.t("err.retry"),
        f"{[(a.status_code, _reason(a)) for a in sequence_a]}")
r.check("(a) … even the correct password then makes nothing fresh (429, no new cookie, /sensitive closed)",
        correct_a.status_code == 429 and _session(auth, correct_a) is None and not _fresh(c),
        f"HTTP {correct_a.status_code}, Cookie {_session(auth, correct_a)!r}")
r.check("(a) … every failed attempt is in the `reauth` bucket and as `failed verification` in the security log "
        "(no `failed login`: the user is already signed in, fail2ban does not ban them)",
        [v[2:4] for v in _attempts(auth, "reauth")] == [(0, "reauth")] * 3
        and len(log_a.lines("failed verification user=alice")) >= 3 and not log_a.lines("failed login"),
        f"{_attempts(auth, 'reauth')} {log_a.lines()[:5]}")
_login_afterwards = _post(_client(app, ("203.0.113.30", 1)), "/auth/login", username="alice", password=PW)
r.check("(a) … own bucket: the typos here do NOT lock the sign-in (303)",
        _login_afterwards.status_code == 303, f"HTTP {_login_afterwards.status_code}")

# Success: fresh, new token (F-06), the old one stays valid for the grace period — without freshness (A-6).
auth, app = _app()
auth.create_user("bert", password=PW)
c = _sign_in(app, "bert")
_stale(auth, c)
_old = c.cookies.get(auth.session_cookie_name)
_before = _fresh(c)
_ok = _post(c, "/own/confirm/password", password=PW)
_new = _session(auth, _ok)
_with_old = TestClient(app, client=IP)
_with_old.cookies.set(auth.session_cookie_name, _old)
r.check("(a) success: 303 to next, new session token in the cookie, the session is fresh (/sensitive 200)",
        not _before and _ok.status_code == 303 and _ok.headers["location"] == "/sensitive"
        and _new and _new != _old and _fresh(c),
        f"fresh before {_before}, HTTP {_ok.status_code} {_ok.headers.get('location')}")
r.check("(a) … the old token stays valid in the grace period, but without freshness; audit `stepup`",
        _with_old.get("/auth/me", headers=JSON).status_code == 200 and not _fresh(_with_old)
        and any(e[0] == "stepup" and e[1] == "bert" for e in _audit(auth)),
        f"{_with_old.get('/auth/me', headers=JSON).status_code} {[e[0] for e in _audit(auth)]}")
_erg_json = TestClient(app, client=IP)
_erg_json.cookies.set(auth.session_cookie_name, _new)
_j = _erg_json.post("/own/confirm-json", json={"password": PW})
r.check("(a) JSON path: the result is `done`, `set_cookie()` puts the next new token in the cookie",
        _j.status_code == 200 and _j.json() == {"reason": "ok", "done": True}
        and _session(auth, _j) not in (None, _new), _j.text[:200])

# IP throttle: the request is throttled before anything is checked or booked.
auth, app = _app(hardening={"rate_limit_max": 3})
auth.create_user("cora", password=PW)
c = _sign_in(app, "cora", ip=("198.51.100.44", 1))
_throttle = [_post(c, "/own/confirm/password", password=f"wrong-{i}") for i in range(5)]
r.check("(a) IP throttle: 429 `ratelimit` with the text of the page",
        _throttle[-1].status_code == 429 and _reason(_throttle[-1]) == "ratelimit"
        and _throttle[-1].json()["message"] == auth.t("err.retry"),
        f"{[(a.status_code, _reason(a)) for a in _throttle]}")


# ── (b) No effect without a session ───────────────────────────────────────────────────────────
# Without a cookie there is nobody whose secret could be checked — and with a HALF
# session (password yes, TOTP pending) neither: a step-up is not a sign-in, it does not turn the
# half session into a full one. Nothing is booked, nothing changed.
# (Mutation probe: in `_only_with_session` `pending_user(request) or session_user(request)` →
# the half session confirms → red.)
auth, app = _app()
uid = auth.create_user("dora", password=PW)
_totp_set_up(auth, uid)
_guest = _client(app)
_without_c = _post(_guest, "/own/confirm/password", password=PW)
_without_p = _post(_guest, "/own/password", current=PW, new=PW_NEW)
_half = _client(app, ("203.0.113.40", 1))
_h1 = _post(_half, "/auth/login", username="dora", password=PW)
_h_tok = _half.cookies.get(auth.session_cookie_name)
_half_c = _post(_half, "/own/confirm/password", password=PW)
_half_p = _post(_half, "/own/password", current=PW, new=PW_NEW)
_h_line = auth.store.get_session(_h_tok)
r.check("(b) without a session: step-up 401 `no_session` with the login page as next_url, password change 401",
        _without_c.status_code == 401 and _reason(_without_c) == "no_session"
        and _without_c.json()["next_url"] == "/auth/login" and _without_c.json()["message"] == auth.t("api.not_signed_in")
        and _without_p.status_code == 401 and _reason(_without_p) == "no_session",
        f"{_without_c.status_code} {_without_c.text[:120]} {_without_p.status_code}")
r.check("(b) half session (TOTP pending): both 401 `no_session`, the session stays half",
        _h1.headers.get("location", "").startswith("/auth/totp")
        and _half_c.status_code == 401 and _reason(_half_c) == "no_session"
        and _half_p.status_code == 401 and _reason(_half_p) == "no_session"
        and _h_line is not None and not _h_line["mfa_ok"],
        f"{_h1.headers.get('location')} {_half_c.status_code} {_half_p.status_code}")
r.check("(b) … nothing booked, nothing changed: no attempt in `reauth`/`password_change`, no audit "
        "`stepup`/`password_change`, the password is the old one",
        not _attempts(auth, "reauth") and not _attempts(auth, "password_change")
        and not [e for e in _audit(auth) if e[0] in ("stepup", "password_change")]
        and auth._verify_user_password(uid, PW),
        f"{_attempts(auth)} {[e[0] for e in _audit(auth)]}")


# ── (c) An API key does not count ─────────────────────────────────────────────────────────────
# A machine key confirms no human and changes no human's password (0.20.1 for
# `/auth/reauth`; for the password change since 0.22.0 — until then `POST /auth/password` took any
# account from `current_user()`, also that of a key, and then ended ALL sessions because none
# was its own). The key is not checked here, it simply does not count: 403 with its
# own text, no attempt, no effect. Not even next to a half session (R6-5).
# (Mutation probe: `current_user` instead of `session_user` in `_only_with_session` → the key confirms
# and changes → red; likewise the guard in `tests/test_stepup.py`.)
auth, app = _app()
uid = auth.create_user("emil", password=PW)
_totp_set_up(auth, uid)
_key = auth.create_api_key(uid, name="automation")["key"]
_sessions_before = len(_sessions(auth, uid))
_k = TestClient(app, client=IP, headers={"X-API-Key": _key})
_k_c = _post(_k, "/own/confirm/password", password=PW)
_k_p = _post(_k, "/own/password", current=PW, new=PW_NEW)
_k_one_c = _k.post("/auth/reauth", data={"password": PW, "next": "/"}, follow_redirects=False)
_k_one_p = _k.post("/auth/password", json={"current": PW, "new": PW_NEW})
r.check("(c) API key instead of session: step-up 403 `no_session` (text `api.stepup_session`), built-in route 403 "
        "with the same text",
        _k_c.status_code == 403 and _reason(_k_c) == "no_session" and _k_c.json()["message"] == auth.t("api.stepup_session")
        and _k_one_c.status_code == 403 and _k_one_c.json()["detail"] == auth.t("api.stepup_session"),
        f"{_k_c.status_code} {_k_c.text[:120]} {_k_one_c.status_code} {_k_one_c.text[:120]}")
r.check("(c) API key instead of session: password change 403 `no_session` (text `api.password_needs_session`), "
        "built-in route likewise",
        _k_p.status_code == 403 and _reason(_k_p) == "no_session"
        and _k_p.json()["detail"] == auth.t("api.password_needs_session")
        and _k_one_p.status_code == 403 and _k_one_p.json()["detail"] == auth.t("api.password_needs_session"),
        f"{_k_p.status_code} {_k_p.text[:120]} {_k_one_p.status_code} {_k_one_p.text[:120]}")
r.check("(c) … no effect: the password is the old one, no attempt booked, no session ended",
        auth._verify_user_password(uid, PW) and not _attempts(auth, "reauth")
        and not _attempts(auth, "password_change") and len(_sessions(auth, uid)) == _sessions_before,
        f"{_attempts(auth)} {len(_sessions(auth, uid))}")
# Next to a half session (same class as R6-5): key + password do not replace the TOTP.
_hk = _client(app, ("203.0.113.41", 1))
_post(_hk, "/auth/login", username="emil", password=PW)
_hk_tok = _hk.cookies.get(auth.session_cookie_name)
_hk.headers["X-API-Key"] = _key
_hk_c = _post(_hk, "/own/confirm/password", password=PW)
_hk_line = auth.store.get_session(_hk_tok)
r.check("(c) half session + API key: 403 `no_session`, the half session stays half",
        _hk_c.status_code == 403 and _reason(_hk_c) == "no_session"
        and _hk_line is not None and not _hk_line["mfa_ok"],
        f"{_hk_c.status_code} {_hk_c.text[:120]} {dict(_hk_line) if _hk_line else None}")


# ── (d) Only offered methods; empty is not an attempt; PIN bucket; TOTP ───────────────────────
# `stepup_methods=["totp"]`: otherwise a custom page with a password field would bypass the default. A not
# offered method is not even checked — 403 `method_disabled`, no failed attempt.
# (Mutation probe: delete the query `if procedure not in methods:` in `_confirm` → the
# password confirms despite `stepup_methods=["totp"]` → red.)
auth, app = _app(stepup_methods=["totp"])
uid = auth.create_user("frida", password=PW)
secret_text = _totp_set_up(auth, uid)
codes = auth.generate_recovery_codes(uid)
c = _sign_in(app, "frida")
_post(c, "/auth/totp", code=pyotp.TOTP(secret_text).now())
_stale(auth, c)
_d_pw = _post(c, "/own/confirm/password", password=PW)
_d_empty = _post(c, "/own/confirm/totp", code="")
_d_rc = _post(c, "/own/confirm/totp", code=codes[0])
_d_attempts = _attempts(auth, "reauth")
r.check("(d) not offered (stepup_methods=[\"totp\"], password sent): 403 `method_disabled`, "
        "nothing fresh, no failed attempt",
        _d_pw.status_code == 403 and _reason(_d_pw) == "method_disabled" and not _fresh(c)
        and _d_pw.json()["message"] == auth.t("err.reauth"),
        f"{_d_pw.status_code} {_d_pw.text[:120]}")
r.check("(d) empty: 400 `missing`, does not count (up to 0.21.x an empty form at /auth/reauth counted)",
        _d_empty.status_code == 400 and _reason(_d_empty) == "missing" and _d_empty.json()["message"] == auth.t("err.required"),
        f"{_d_empty.status_code} {_d_empty.text[:120]}")
r.check("(d) one-time code instead of TOTP: 401 `invalid` — the step-up takes only TOTP, like the built-in page; "
        "exactly this one attempt was counted",
        _d_rc.status_code == 401 and _reason(_d_rc) == "invalid" and [v[2] for v in _d_attempts] == [0]
        and auth.recovery_codes_remaining(uid) == len(codes),
        f"{_d_rc.status_code} {_d_attempts} {auth.recovery_codes_remaining(uid)}")
_d_ok = _post(c, "/own/confirm/totp", code=pyotp.TOTP(secret_text).at(time.time() + 30))
r.check("(d) … a TOTP code confirms: 303, fresh", _d_ok.status_code == 303 and _fresh(c),
        f"{_d_ok.status_code} {_d_ok.text[:120]}")

# `stepup_strict` without a set-up method: nothing this account could confirm with.
auth, app = _app(stepup_methods=["totp"], stepup_strict=True)
auth.create_user("gerd", password=PW)
c = _sign_in(app, "gerd")
_strict = _post(c, "/own/confirm/password", password=PW)
r.check("(d) stepup_strict without TOTP: 403 `method_disabled` with the text of the page (err.stepup_none), "
        "no attempt",
        _strict.status_code == 403 and _reason(_strict) == "method_disabled"
        and _strict.json()["message"] == auth.t("err.stepup_none") and not _attempts(auth, "reauth"),
        f"{_strict.status_code} {_strict.text[:120]}")

# PIN (C-3): if the page offers the PIN, the PIN bucket applies too — a PIN locked at the PIN login
# cannot be guessed on here, not even with the password next to it.
auth, app = _app(pin_enabled=True, pin_login=True, hardening={"pin_max_attempts": 2})
uid = auth.create_user("hanna", password=PW)
auth.set_pin(uid, PIN)
c = _sign_in(app, "hanna")
_stale(auth, c)
_p_ok = _post(c, "/own/confirm/pin", pin=PIN)
_stale(auth, c)
for i in range(2):
    _post(_client(app), "/auth/pin", username="hanna", pin=f"000{i}")
_p_locked = _post(c, "/own/confirm/pin", pin=PIN)
_pw_locked = _post(c, "/own/confirm/password", password=PW)
r.check("(d) PIN: correct PIN confirms (303); after the PIN lock at login 429 `locked` — also with the "
        "password, as long as the page offers the PIN (C-3)",
        _p_ok.status_code == 303 and _p_locked.status_code == 429 and _reason(_p_locked) == "locked"
        and _pw_locked.status_code == 429 and not _fresh(c),
        f"{_p_ok.status_code} {_p_locked.status_code} {_pw_locked.status_code}")
auth, app = _app(pin_enabled=False)
uid = auth.create_user("ines", password=PW)
auth.set_pin(uid, PIN)
c = _sign_in(app, "ines")
_p_from = _post(c, "/own/confirm/pin", pin=PIN)
r.check("(d) without pin_enabled: `confirm_pin` 403 `method_disabled`, despite the PIN hash in the database",
        _p_from.status_code == 403 and _reason(_p_from) == "method_disabled", f"{_p_from.status_code}")


# ── (e) Custom password-change page ───────────────────────────────────────────────────────────
# The old password is a secret like at login (R4-10): throttled, locked in its own bucket,
# logged. Until 0.21.x a custom page had only `set_password` and the inner verifiers for this.
# (Mutation probe: switch off the rejection `if attempt is None:` in `change_password` → fourth
# response 403, the correct password 200 → red.)
auth, app = _app(hardening={"password_change_max_attempts": 3})
uid = auth.create_user("jana", password=PW)
c = _sign_in(app, "jana")
with Recording() as log_e:
    sequence_e = [_post(c, "/own/password", current=f"wrong-{i}", new=PW_NEW) for i in range(4)]
    correct_e = _post(c, "/own/password", current=PW, new=PW_NEW)
r.check("(e) custom password-change page: after 3 failed attempts 429 `locked` — even the correct old "
        "password then changes nothing",
        [a.status_code for a in sequence_e] == [403, 403, 403, 429] and _reason(sequence_e[0]) == "invalid"
        and sequence_e[0].json()["detail"] == auth.t("api.password_wrong")
        and _reason(sequence_e[-1]) == "locked" and sequence_e[-1].json()["detail"] == auth.t("api.too_many")
        and correct_e.status_code == 429 and auth._verify_user_password(uid, PW),
        f"{[(a.status_code, _reason(a)) for a in sequence_e]} {correct_e.status_code}")
r.check("(e) … in the `password_change` bucket, with a line in the security log; the sign-in stays open",
        [v[2:4] for v in _attempts(auth, "password_change")] == [(0, "password_change")] * 3
        and len(log_e.lines("failed verification user=jana")) >= 3
        and _post(_client(app, ("203.0.113.31", 1)), "/auth/login", username="jana", password=PW).status_code == 303,
        f"{_attempts(auth, 'password_change')} {log_e.lines()[:4]}")

# Success: new password, the OTHER sessions end (one's own stays), pending address-change links
# are dropped, API keys stay and are mentioned.
# (Mutation probe: delete `delete_user_sessions_except` in `change_password` → red.)
auth, app = _app()
uid = auth.create_user("karla", password=PW)
auth.create_api_key(uid, name="automation")
c = _sign_in(app, "karla")
_other = _sign_in(app, "karla", ip=("203.0.113.50", 1))
_change = auth.create_magic_token("email_change", user_id=uid)
_sign_in_link = auth.create_magic_token("login", user_id=uid)
_weak = _post(c, "/own/password", current=PW, new="short")
_empty = _post(c, "/own/password", current="", new=PW_NEW)
_e_ok = _post(c, "/own/password", current=PW, new=PW_NEW)


def _link_unclosed(raw):
    return auth.store.get_magic_token(hashlib.sha256(raw.encode()).hexdigest()) is not None


r.check("(e) new password too weak: 400 `policy` with the violated rule as text",
        _weak.status_code == 400 and _reason(_weak) == "policy"
        and _weak.json()["detail"] == auth.password_policy_error("short", username="karla", api=True),
        f"{_weak.status_code} {_weak.text[:160]}")
r.check("(e) empty old password: 400 `missing`, does not count",
        _empty.status_code == 400 and _reason(_empty) == "missing" and not [
            v for v in _attempts(auth, "password_change") if not v[2]],
        f"{_empty.status_code} {_attempts(auth, 'password_change')}")
r.check("(e) success: 200 with api_keys_active=1, the new password applies, one's own session continues",
        _e_ok.status_code == 200 and _e_ok.json() == {"ok": True, "api_keys_active": 1}
        and auth._verify_user_password(uid, PW_NEW) and c.get("/auth/me", headers=JSON).status_code == 200,
        f"{_e_ok.status_code} {_e_ok.text[:160]}")
r.check("(e) … the other session is ended, the pending address change discarded, the sign-in link not",
        _other.get("/auth/me", headers=JSON).status_code == 401 and not _link_unclosed(_change)
        and _link_unclosed(_sign_in_link),
        f"{_other.get('/auth/me', headers=JSON).status_code} {_link_unclosed(_change)} {_link_unclosed(_sign_in_link)}")
r.check("(e) … audit `password_change` with `api_keys_active=1`",
        ("password_change", "karla", IP[0], "api_keys_active=1") in _audit(auth), str(_audit(auth)[-3:]))


# ── (f) CSRF and the result type ──────────────────────────────────────────────────────────────
# Like every write route: `csrf=` (form field) or, without the argument, the X-CSRF-Token header.
# (Mutation probe: delete the line `self.require_csrf(…)` in `_confirm` resp. `change_password`
# → without token 303 resp. 200 → red.)
auth, app = _app(csrf_enabled=True)
uid = auth.create_user("lena", password=PW)
c = _client(app)
c.get("/auth/login")
c.post("/auth/login", data={"username": "lena", "password": PW, "next": "/",
                            "_csrf": c.cookies.get(auth.csrf_cookie_name)}, follow_redirects=False)
_tok = c.cookies.get(auth.csrf_cookie_name)
_f_c_without = _post(c, "/own/confirm/password", password=PW)
_f_p_without = _post(c, "/own/password", current=PW, new=PW_NEW)
_f_pj_without = c.post("/own/password-json", json={"current": PW, "new": PW_NEW})
_f_booked = _attempts(auth, "reauth") + _attempts(auth, "password_change")
_f_pw_old = auth._verify_user_password(uid, PW)
_f_c_with = _post(c, "/own/confirm/password", password=PW, _csrf=_tok)
_f_cj_with = c.post("/own/confirm-json", json={"password": PW}, headers={"X-CSRF-Token": _tok})
_f_p_empty = c.post("/own/password", data={"current": PW, "new": PW_NEW, "_csrf": ""},
                   headers={"X-CSRF-Token": _tok})
_f_pj_with = c.post("/own/password-json", json={"current": PW, "new": PW_NEW}, headers={"X-CSRF-Token": _tok})
r.check("(f) CSRF: without token 403 (step-up, password change as form and as JSON), nothing changed",
        _f_c_without.status_code == 403 and _f_p_without.status_code == 403 and _f_pj_without.status_code == 403
        and not _f_booked and _f_pw_old,
        f"{_f_c_without.status_code} {_f_p_without.status_code} {_f_pj_without.status_code} {_f_booked} {_f_pw_old}")
r.check("(f) … with token in the field resp. `csrf=None` + header: 303 resp. 200; an empty form field does "
        "NOT fall back to the header (403)",
        _f_c_with.status_code == 303 and _f_cj_with.status_code == 200 and _f_p_empty.status_code == 403
        and _f_pj_with.status_code == 200 and auth._verify_user_password(uid, PW_NEW),
        f"{_f_c_with.status_code} {_f_cj_with.status_code} {_f_p_empty.status_code} {_f_pj_with.status_code}")

_fields = {f.name for f in dataclasses.fields(PasswordChangeResult)}
_pc = PasswordChangeResult(ok=True, reason="ok", status=200, api_keys_active=2)
try:
    _pc.ok = False                       # type: ignore[misc]
    _frozen = False
except dataclasses.FrozenInstanceError:
    _frozen = True
_wrong_built = []
for kw in ({"ok": False, "reason": "invented", "status": 400}, {"ok": True, "reason": "invalid", "status": 200},
           {"ok": False, "reason": "ok", "status": 200}):
    try:
        PasswordChangeResult(**kw)
        _wrong_built.append(kw)
    except ValueError:
        pass  # expected: the constructor rejects the combination
r.check("(f) PasswordChangeResult: fields ok/reason/status/message/api_keys_active, bool = ok, frozen, "
        "a reason outside REASONS or an ok contradicting the reason raises",
        _fields == {"ok", "reason", "status", "message", "api_keys_active"} and bool(_pc)
        and not PasswordChangeResult(ok=False, reason="invalid", status=403) and _frozen and not _wrong_built,
        f"{_fields} {_frozen} {_wrong_built}")
r.check("(f) every reason the block returns is in REASONS (the ones measured above)",
        set(PasswordChangeResult.REASONS) == {"ok", "missing", "invalid", "locked", "ratelimit", "policy",
                                                "no_session"}, str(PasswordChangeResult.REASONS))
r.check("(f) the step-up blocks return a `LoginResult` (the same form as the sign-in), "
        "`change_password` a `PasswordChangeResult`",
        all(inspect.signature(getattr(TinySesam, n)).return_annotation in (LoginResult, "LoginResult")
            for n in ("confirm_password", "confirm_pin", "confirm_totp"))
        and inspect.signature(TinySesam.change_password).return_annotation in (PasswordChangeResult,
                                                                              "PasswordChangeResult"),
        "return types")


# ── (g) Equality with the built-in routes ─────────────────────────────────────────────────────
# The same sequence once via `/auth/reauth` resp. `POST /auth/password`, once via the custom
# route — each in a fresh instance. Must be equal: status, redirect target resp. text,
# audit rows, security log and the attempts table. This is the proof for "one source".
_secrets: dict = {}


def _execution(built_in: bool, steps, setup):
    auth, app, c = setup()
    result = []
    with Recording() as log:
        for kind, value in steps(auth):
            if kind == "new_password":
                current, new = value
                a = (c.post("/auth/password", json={"current": current, "new": new}) if built_in
                     else _post(c, "/own/password", current=current, new=new))
                result.append((a.status_code, a.json().get("detail"), a.json().get("api_keys_active")))
                continue
            slot = {"password": "password", "pin": "pin", "totp": "code"}[kind]
            a = (_post(c, "/auth/reauth", **{slot: value}) if built_in
                 else _post(c, f"/own/confirm/{kind}", **{slot: value}))
            result.append((a.status_code, a.headers.get("location")))
    return dict(status=result, audit=_audit(auth), log=log.lines(), attempts=_attempts(auth))


def _comparison(name, steps, setup):
    one, own = _execution(True, steps, setup), _execution(False, steps, setup)
    deviating = [k for k in one if one[k] != own[k]]
    r.check(f"(g) {name}: built-in and custom route — the same status, audit, log and counter rows",
            not deviating and len(one["audit"]) >= 3 and one["log"],
            "; ".join(f"{k}: built-in {one[k]} ≠ custom {own[k]}" for k in deviating)[:900]
            or f"too little measured: {one}")
    return one


def _sign_in_with_totp(app, name, secret_text):
    """A full session with TOTP. The set-up code (30 s ago) is used up — each one is valid
    once —, so the current one signs in, and the step-up then takes the next."""
    c = _client(app)
    _post(c, "/auth/login", username=name, password=PW)
    a = _post(c, "/auth/totp", code=pyotp.TOTP(secret_text).now())
    assert a.status_code == 303, (name, a.status_code, a.text[:200])
    return c


def _setup_stepup():
    auth, app = _app(pin_enabled=True, hardening={"reauth_max_attempts": 4})
    uid = auth.create_user("otto", password=PW)
    auth.set_pin(uid, PIN)
    _secrets[id(auth)] = _totp_set_up(auth, uid)
    return auth, app, _sign_in_with_totp(app, "otto", _secrets[id(auth)])


def _stepup_steps(auth):
    g = _secrets[id(auth)]
    yield "password", "wrong-1"
    yield "pin", ""
    yield "pin", "0000"
    yield "totp", "000000"
    yield "password", PW                                   # correct: clears the `reauth` bucket
    yield "totp", pyotp.TOTP(g).at(time.time() + 30)       # correct (the next code)
    for i in range(4):
        yield "pin", f"000{i}"
    yield "password", PW                                   # locked


_g_su = _comparison("Step-up (password, PIN, TOTP; wrong, empty, right, lock)", _stepup_steps, _setup_stepup)
r.check("(g) … step-up sequence: 401, 400, 401, 401, 303, 303, 401×4, 429",
        [s for s, _ in _g_su["status"]] == [401, 400, 401, 401, 303, 303, 401, 401, 401, 401, 429],
        str(_g_su["status"]))


def _setup_only_totp():
    auth, app = _app(stepup_methods=["totp"])
    uid = auth.create_user("paula", password=PW)
    _secrets[id(auth)] = _totp_set_up(auth, uid)
    return auth, app, _sign_in_with_totp(app, "paula", _secrets[id(auth)])


def _only_totp_steps(auth):
    yield "password", PW                                   # not offered: 403, does not count
    yield "totp", "000000"
    yield "totp", pyotp.TOTP(_secrets[id(auth)]).at(time.time() + 30)


_g_nt = _comparison("stepup_methods=[\"totp\"] (password not offered, TOTP wrong, correct)",
                   _only_totp_steps, _setup_only_totp)
r.check("(g) … TOTP-only sequence: 403, 401, 303", [s for s, _ in _g_nt["status"]] == [403, 401, 303],
        str(_g_nt["status"]))


def _setup_password():
    auth, app = _app(hardening={"password_change_max_attempts": 3})
    uid = auth.create_user("quirin", password=PW)
    auth.create_api_key(uid, name="automation")
    return auth, app, _sign_in(app, "quirin")


_g_pw = _comparison("password change (wrong, empty, too weak, lock, then correct)", lambda a: [
    ("new_password", ("wrong-1", PW_NEW)),
    ("new_password", ("", PW_NEW)),
    ("new_password", (PW, "short")),                      # old one correct: clears the bucket
    ("new_password", ("wrong-2", PW_NEW)),
    ("new_password", ("wrong-3", PW_NEW)),
    ("new_password", ("wrong-4", PW_NEW)),
    ("new_password", (PW, PW_NEW)),                      # locked
], _setup_password)
r.check("(g) … password sequence: 403, 400, 400, 403, 403, 403, 429",
        [s for s, _, _ in _g_pw["status"]] == [403, 400, 400, 403, 403, 403, 429], str(_g_pw["status"]))
_g_pw_ok = _comparison("password change (success with API key, then the old password wrong)", lambda a: [
    ("new_password", (PW, PW_NEW)),
    ("new_password", (PW, "Still-A-New1xxx")),
    ("new_password", (PW_NEW, "Still-A-New1xxx")),
], _setup_password)
r.check("(g) … success sequence: 200 with api_keys_active=1, 403, 200",
        _g_pw_ok["status"] == [(200, None, 1), (403, auth.t("api.password_wrong"), None), (200, None, 1)],
        str(_g_pw_ok["status"]))


# ── (h) One source: the routes call the block, no inner verifier ──────────────────────────────
# If the check were there twice — in the route and in the block —, it would drift apart, and the
# block would be the weaker path. The routes may call the block and render the result
# (`/auth/reauth` asks `session_user`/`stepup_options` for the display); every name of the
# check, bookkeeping and effect is forbidden to them.
# (Mutation probe: call `auth._verify_user_password(…)` again in `reauth_submit` → red.)
INNER = {"_verify_user_password", "_verify_user_pin", "_verify_totp", "_verify_recovery_code",
          "_check_password", "_check_pin", "_begin_attempt", "_attempt_failed", "_record_login",
          "_rate_ok", "_is_reauth_locked", "_is_password_change_locked", "_only_with_session",
          "set_session_mfa", "rotate_session", "set_password", "delete_user_sessions_except",
          "revoke_user_magic_tokens", "count_active_api_keys", "password_policy_error", "audit",
          "require_csrf", "_session_from_request"}
ROUTES = {"reauth_submit": {"confirm_password", "confirm_pin", "confirm_totp"},
          "change_own_password": {"change_password"}}


def _routes_findings(source_text):
    findings, found = [], set()
    for fn in ast.walk(ast.parse(source_text)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name not in ROUTES:
            continue
        found.add(fn.name)
        names = {k.attr for k in ast.walk(fn) if isinstance(k, ast.Attribute)}
        findings += [f"{fn.name} does not call {n}" for n in sorted(ROUTES[fn.name] - names)]
        findings += [f"{fn.name} calls {n} itself" for n in sorted(names & INNER)]
    findings += [f"{n} missing in the router" for n in sorted(set(ROUTES) - found)]
    return findings


_itself = {
    "clean": ("def reauth_submit(r):\n    e = auth.confirm_totp(r, 'c') if c else auth.confirm_pin(r, 'p')\n"
               "    return e or auth.confirm_password(r, 'x')\n"
               "async def change_own_password(r):\n    return await run_in_threadpool(auth.change_password, r)\n", []),
    "double": ("def reauth_submit(r):\n    auth._verify_user_password(1, 'x')\n"
                "    return auth.confirm_totp(r, 'c') or auth.confirm_pin(r, 'p') or auth.confirm_password(r, 'x')\n"
                "async def change_own_password(r):\n    auth.set_password(1, 'n')\n"
                "    return auth.change_password(r, 'a', 'b')\n",
                ["reauth_submit calls _verify_user_password itself", "change_own_password calls set_password itself"]),
    "over": ("def reauth_submit(r):\n    return auth.confirm_password(r, 'x')\n", None),
}
_router = (ROOT / "tinysesam" / "router.py").read_text(encoding="utf-8")
for _probe, (_text, _expected) in _itself.items():
    _b = _routes_findings(_text)
    if _expected is None:
        assert "reauth_submit does not call confirm_pin" in _b and "change_own_password missing in the router" in _b, _b
    else:
        assert _b == _expected, (_probe, _b)
_findings_h = _routes_findings(_router)
r.check("(h) one source: reauth_submit calls confirm_*, change_own_password calls change_password — no "
        "inner verifiers, no bookkeeping, no effect itself (AST, 3 self-probes)",
        not _findings_h, "; ".join(_findings_h))


# ── (i) The README examples run verbatim ──────────────────────────────────────────────────────
# With the default configuration (CSRF on, secure cookies, five failed attempts per bucket): the custom
# step-up page must lock after the limit and make fresh with the correct password, the
# custom password-change page likewise lock and change. `test_repo.py` only executes the blocks.
# (Mutation probe: replace `auth.confirm_password(…)` in the README example with the old pattern
# `auth._verify_user_password(…)` + `rotate_session` → no 429 → red.)
def _readme_example(file, head):
    text = (ROOT / file).read_text(encoding="utf-8")
    section = text.split(head, 1)[1].split("\n## ", 1)[0]
    blocks = re.findall(r"```python\n(.*?)```", section, re.S)
    return blocks[0] if blocks else ""


def _readme_app(file, head):
    source = _readme_example(file, head)
    db = str(Path(tempfile.mkdtemp()) / "app.db")
    ns: dict = {"__name__": "readme_example"}
    exec(compile(source.replace('db_path="app.db"', f"db_path={db!r}"), file, "exec"), ns)   # noqa: S102
    return source, ns["auth"], ns["app"]


def _readme_sign_in(auth_r, app_r, name, ip):
    c = TestClient(app_r, base_url="https://testserver", client=ip)
    c.get("/auth/login")
    a = c.post("/auth/login", data={"username": name, "password": PW, "next": "/",
                                    "_csrf": c.cookies.get(auth_r.csrf_cookie_name)}, follow_redirects=False)
    assert a.status_code == 303, (name, a.status_code, a.text[:200])
    return c


for _file, _head, _path, _sensitive in (("README.md", "## Own step-up page\n", "/confirm", "/danger"),
                                        ("i18n/README.de.md", "## Eigene Step-up-Seite\n", "/bestaetigen",
                                         "/gefaehrlich")):
    _source, _auth, _app_r = _readme_app(_file, _head)
    _auth.create_user("rosa", password=PW)
    _auth.create_user("sven", password=PW)
    _limit = _auth.all_security()["reauth_max_attempts"]
    _c = _readme_sign_in(_auth, _app_r, "rosa", IP)
    _stale(_auth, _c)
    _to = _c.get(_sensitive, headers=JSON, follow_redirects=False)
    _tok = _c.cookies.get(_auth.csrf_cookie_name)
    _sequence = [_c.post(_path, data={"password": f"wrong-{i}", "next": _sensitive, "_csrf": _tok},
                      follow_redirects=False).status_code for i in range(_limit + 1)]
    _locked = _c.post(_path, data={"password": PW, "next": _sensitive, "_csrf": _tok}, follow_redirects=False)
    _c2 = _readme_sign_in(_auth, _app_r, "sven", ("203.0.113.77", 1))
    _stale(_auth, _c2)
    _without_csrf = _c2.post(_path, data={"password": PW, "next": _sensitive}, follow_redirects=False)
    _free = _c2.post(_path, data={"password": PW, "next": _sensitive, "_csrf": _c2.cookies.get(_auth.csrf_cookie_name)},
                     follow_redirects=False)
    r.check(f"(i) {_file}: the example “custom step-up page” locks after {_limit} failed attempts (429), "
            "requires CSRF (403) and makes fresh with the correct password (303 to next, new cookie)",
            "confirm_password" in _source and _to.status_code == 403 and _to.headers.get("X-TinySesam-Reauth")
            and _sequence == [401] * _limit + [429] and _locked.status_code == 429
            and _c.get(_sensitive, headers=JSON).status_code == 403 and _without_csrf.status_code == 403
            and _free.status_code == 303 and _free.headers["location"] == _sensitive
            and _free.cookies.get(_auth.session_cookie_name) and _c2.get(_sensitive, headers=JSON).status_code == 200,
            f"{_to.status_code} {_sequence} {_locked.status_code} {_without_csrf.status_code} {_free.status_code}")

for _file, _head, _path in (("README.md", "## Own password change page\n", "/password"),
                             ("i18n/README.de.md", "## Eigene Passwortwechsel-Seite\n", "/passwort")):
    _source, _auth, _app_r = _readme_app(_file, _head)
    _uid_t = _auth.create_user("theo", password=PW)
    _uid_u = _auth.create_user("uwe", password=PW)
    _auth.create_api_key(_uid_u, name="automation")
    _limit = _auth.all_security()["password_change_max_attempts"]
    _c = _readme_sign_in(_auth, _app_r, "theo", IP)
    _tok = _c.cookies.get(_auth.csrf_cookie_name)
    _sequence = [_c.post(_path, data={"current": f"wrong-{i}", "new": PW_NEW, "_csrf": _tok}).status_code
              for i in range(_limit + 1)]
    _locked = _c.post(_path, data={"current": PW, "new": PW_NEW, "_csrf": _tok})
    _c2 = _readme_sign_in(_auth, _app_r, "uwe", ("203.0.113.78", 1))
    _c3 = _readme_sign_in(_auth, _app_r, "uwe", ("203.0.113.79", 1))
    _without_csrf = _c2.post(_path, data={"current": PW, "new": PW_NEW})
    _free = _c2.post(_path, data={"current": PW, "new": PW_NEW, "_csrf": _c2.cookies.get(_auth.csrf_cookie_name)})
    r.check(f"(i) {_file}: the example “custom password-change page” locks after {_limit} failed attempts "
            "(429, password unchanged), requires CSRF (403), changes (200), ends the other session and "
            "mentions the API key",
            "change_password" in _source and _sequence == [403] * _limit + [429] and _locked.status_code == 429
            and _auth._verify_user_password(_uid_t, PW) and _without_csrf.status_code == 403
            and _free.status_code == 200 and "API" in _free.text and _auth._verify_user_password(_uid_u, PW_NEW)
            and _c3.get("/auth/me", headers=JSON).status_code == 401,
            f"{_sequence} {_locked.status_code} {_without_csrf.status_code} {_free.status_code} {_free.text[:120]}")


# ── (j) The names: English, each one in tier A ────────────────────────────────────────────────
# As with the login block (`test_sign_in.py`, k): the surface is measured on the live object —
# every method that returns a `PasswordChangeResult`, with parameters; name, module, fields,
# constants and the values of `REASONS` — and held against the ONE word list from `test_api_surface.py`.
# `confirm_*` return a `LoginResult` and are therefore already in `test_sign_in.py` (k);
# here all that counts is that they are measured along there and carry tier A.
# (Mutation probes, each individually: append a reason "gesperrt" to `PasswordChangeResult.REASONS`
# → red; set `TinySesam.change_password` to tier "B" in `api_surface.json` → red.)
from test_api_surface import german_in  # noqa: E402

_storage = json.loads((ROOT / "tests" / "api_surface.json").read_text(encoding="utf-8"))
_deliver = sorted(n for n, f in vars(TinySesam).items()
                  if inspect.isfunction(f) and not n.startswith("_")
                  and inspect.signature(f).return_annotation in (PasswordChangeResult, "PasswordChangeResult"))
_names = {("tinysesam", PasswordChangeResult.__name__), ("Module", PasswordChangeResult.__module__)}
for _n in _deliver + ["confirm_password", "confirm_pin", "confirm_totp"]:
    _names.add(("TinySesam", _n))
    _names |= {(f"TinySesam.{_n}()", p) for p in inspect.signature(vars(TinySesam)[_n]).parameters if p != "self"}
_names |= {("PasswordChangeResult", f.name) for f in dataclasses.fields(PasswordChangeResult)}
_names |= {("PasswordChangeResult", n) for n in vars(PasswordChangeResult) if not n.startswith("_")}
_names |= {("PasswordChangeResult.REASONS", w) for w in PasswordChangeResult.REASONS}
_german = [f"{where}: {name!r}" for where, name in sorted(_names) if german_in(name)]
_tier = [f"{b}.{n}: {(_storage.get(b, {}).get(n) or {}).get('tier')!r}"
          for b, n in ([("TinySesam", m) for m in _deliver + ["confirm_password", "confirm_pin", "confirm_totp"]]
                       + [("exports", "PasswordChangeResult")]
                       + [("PasswordChangeResult", f.name) for f in dataclasses.fields(PasswordChangeResult)]
                       + [("PasswordChangeResult", "REASONS")])
          if (_storage.get(b, {}).get(n) or {}).get("tier") != "A"]
assert german_in("gesperrt") and not german_in("api_keys_active"), "word list measures nothing"
r.check(f"(j) the tier-A surface is English: {len(_names)} names ({', '.join(_deliver)}, confirm_*, "
        "`PasswordChangeResult` with fields and reasons), no German word; every name in tier A",
        _deliver == ["change_password"] and len(_names) >= 25 and not _german and not _tier,
        "; ".join(_german + _tier) or f"too little measured: {_deliver} {len(_names)}")


sys.exit(r.done())
