"""Session handles are keyed with the pepper (T-71).

Up to 0.26.0 a session row stored the plain sha256 of the cookie. Whoever could WRITE the database file — a stolen
backup put back, a shared volume, an injection elsewhere — inserted the sha256 of a token of their own choosing and
held a session of any account, without any key. Since T-71 the handle is an HMAC with the pepper keyring (ADR-12),
which never lives readable in the file. Pinned here:

  (a) a planted plain-sha256 row signs nobody in; a real cookie still does
  (b) no start rewrites a handle: a planted plain-sha256 row (marker deleted) stays worthless across restarts
  (c) after a pepper rotation running sessions stay valid, new ones take the active pepper, and `keys retire`
      refuses while a session from before the rotation still runs
  (d) a store without the pepper refuses instead of falling back to the plain digest
  (e) T-72: API keys, one-time tokens (sign-in links, invitations, confirmations, pairing and QR codes) and the QR
      device secret are keyed the same way — a planted plain sha256 opens nothing, every store path uses the keyed
      digest, and a pepper rotation keeps them valid until `keys retire` (which refuses while one still needs it)
  (f) recovery codes (@344f94) likewise: a planted plain sha256 is no second factor, a pepper rotation keeps unused
      codes valid, and `keys retire` refuses while one from before the rotation is unused

    python tests/run_all.py test_session_pepper.py
"""
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.store import Store  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Session handles keyed with the pepper (T-71)")


def make(db=None, **over):
    cfg = dict(db_path=db or os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False, lang="en")
    cfg.update(over)
    return TinySesam(TinySesamConfig(**cfg))


def plain(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def peppered(pepper: bytes, token: str) -> str:
    # Computed here, not through `Store.session_hash`: a test that asks the function it checks stays green when the
    # function mutates.
    return hmac.new(pepper, b"tinysesam/session-handle/v1\x00" + plain(token).encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- (a) a planted row
auth = make()
uid = auth.create_user("victim", password="a long probe password 4711")
real = auth.store.create_session(uid, 3600, True, "password")
pepper = auth._pepper_keyring.active.material
r.check("(a) the stored handle is the HMAC with the pepper, not the sha256 of the cookie",
        [z["token_hash"] for z in auth.store._all("SELECT token_hash FROM session")] == [peppered(pepper, real)])
chosen = secrets.token_urlsafe(32)
now = int(time.time())
auth.store._exec("INSERT INTO session(token_hash, user_id, created_at, expires_at, mfa_ok, mfa_at, method) "
                 "VALUES (?, ?, ?, ?, 1, ?, 'password')", (plain(chosen), uid, now, now + 3600, now))
r.check("(a) a row planted with the sha256 of a chosen token signs nobody in",
        auth.store.get_session(chosen) is None, "write access to the file mints a session of any account")
r.check("(a) the real cookie still signs in (counter-check)", auth.store.get_session(real) is not None)
auth.close()

# ---------------------------------------------------------------- (b) no rewrite at start
# Up to 0.30.0 the start rewrote plain sha256 handles with the pepper whenever the marker `session_handles` was missing
# (the transition from 0.26.0). Whoever could write the file deleted the marker, planted a plain sha256 row and waited
# for a restart — the rewrite turned it into a valid session. Since the schema baseline (T-111) no start rewrites
# anything: the planted row stays worthless across restarts.
db = os.path.join(tempfile.mkdtemp(), "planted.db")
prep = make(db)
ouid = prep.create_user("olga", password="a long probe password 4711")
prep.close()
st = Store(db)
chosen, link, unlock = (secrets.token_urlsafe(32) for _ in range(3))
now = int(time.time())
st._exec("INSERT INTO session(token_hash, user_id, created_at, expires_at, mfa_ok, mfa_at, method) "
         "VALUES (?, ?, ?, ?, 1, ?, 'password')", (plain(chosen), ouid, now, now + 3600, now))
st._exec("INSERT INTO gate_link(link_hash, token_hash, host, created_at) VALUES (?, ?, 'app.example.com', ?)",
         (plain(link), plain(chosen), now))
st._exec("INSERT INTO resource_unlock(token, resource, expires_at) VALUES (?, 'file-1', ?)", (plain(unlock), now + 3600))
st._exec("DELETE FROM setting WHERE key='session_handles'")      # the marker the transition looked for
st.close()
for round_ in ("first", "second"):
    up = make(db)
    r.check(f"(b) {round_} start after planting: the plain sha256 session, app-host link and area unlock grant nothing",
            up.store.get_session(chosen) is None
            and up.store.gate_link_handle(up.store.session_hash(link), "app.example.com") is None
            and not up.store.is_resource_unlocked(unlock, "file-1")
            and up.store._one("SELECT token_hash FROM session WHERE user_id=?", (ouid,))["token_hash"] == plain(chosen),
            "a start rewrote the planted rows into valid ones")
    up.close()

# ---------------------------------------------------------------- (c) pepper rotation
db = os.path.join(tempfile.mkdtemp(), "rot.db")
a = make(db)
uid = a.create_user("rita", password="a long probe password 4711")
before = a.store.create_session(uid, 3600, True, "password")
old_kid = a._pepper_keyring.active.kid
a.close()
env = dict(os.environ, PYTHONPATH=str(ROOT))
env.pop("TINYSESAM_OAUTH_PEPPER", None)
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "rotate", "--purpose", "oauth-pepper", "--db", db],
                     capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))
r.check("(c) `keys rotate --purpose oauth-pepper` runs", out.returncode == 0, out.stderr[-300:])
b = make(db)
r.check("(c) the session from before the rotation stays valid", b.store.get_session(before) is not None)
after = b.store.create_session(uid, 3600, True, "password")
r.check("(c) a new session takes the active pepper",
        b._pepper_keyring.active.kid != old_kid
        and b.store._one("SELECT 1 FROM session WHERE token_hash=?",
                         (peppered(b._pepper_keyring.active.material, after),)) is not None)
b.close()
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "retire", "--purpose", "oauth-pepper", "--db", db],
                     capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))
r.check("(c) `keys retire` refuses while a session from before the rotation runs",
        out.returncode == 1 and "session(s)" in out.stderr, (out.stdout + out.stderr)[-300:])
c = make(db)
r.check("(c) … and the refused retire left the session alone", c.store.get_session(before) is not None)
c.close()

# ---------------------------------------------------------------- (d) no pepper, no digest
bare = Store(os.path.join(tempfile.mkdtemp(), "bare.db"))
try:
    bare.session_hash("anything")
    refused = False
except RuntimeError:
    refused = True
try:
    bare.token_digest("tsk_anything", "apikey")
    refused_t = False
except RuntimeError:
    refused_t = True
r.check("(d) a store without the pepper refuses to digest a session token or an API key (no silent sha256)",
        refused and refused_t)
bare.close()


# ---------------------------------------------------------------- (e) the other token digests (T-72)
def token_peppered(pepper: bytes, kind: str, raw: str) -> str:
    # Computed here, not through `Store.token_digest` (as `peppered` above).
    return hmac.new(pepper, b"tinysesam/token/v1\x00" + kind.encode() + b"\x00" + raw.encode(), hashlib.sha256).hexdigest()


t = make(os.path.join(tempfile.mkdtemp(), "tok.db"), qr_login_enabled=True, base_url="https://auth.example.com")
tuid = t.create_user("tom", password="a long probe password 4711")
tp = t._pepper_keyring.active.material
tok_ci = t.create_api_key(tuid, name="ci")["key"]
link = t.create_magic_token("login", user_id=tuid)
r.check("(e) an API key and a sign-in link are stored as the HMAC with the pepper, not as their sha256",
        t.store._one("SELECT key_hash FROM api_key")["key_hash"] == token_peppered(tp, "apikey", tok_ci)
        and t.store._one("SELECT 1 FROM magic_token WHERE token_hash=?",
                         (token_peppered(tp, "magic", link),)) is not None
        and t.verify_api_key(tok_ci)[0] is not None and t.peek_magic(link) is not None)
now = int(time.time())
planted_api, chosen_link = "tsk_" + secrets.token_urlsafe(32), secrets.token_urlsafe(32)
t.store._exec("INSERT INTO api_key(user_id, name, prefix, key_hash, created_at) VALUES (?, 'planted', 'tsk_x', ?, ?)",
              (tuid, plain(planted_api), now))
for purpose in ("login", "invite", "verify_email"):
    t.store._exec("INSERT INTO magic_token(token_hash, purpose, user_id, created_at, expires_at) VALUES (?,?,?,?,?)",
                  (plain(chosen_link + purpose), purpose, tuid, now, now + 3600))
r.check("(e) a row planted with the sha256 of a chosen API key mints no key; a planted sign-in link, invitation or "
        "address confirmation opens nothing",
        t.verify_api_key(planted_api) == (None, None) and t.api_key_kind(planted_api) == ""
        and all(t.peek_magic(chosen_link + p) is None and t.redeem_magic(chosen_link + p) is None
                for p in ("login", "invite", "verify_email")),
        "write access to the file mints a key or a link")
# QR sign-in: a planted code (sha256 of `qr:<code>`) is no open request, and a real request does not take a device
# secret whose plain sha256 was planted in its payload.
qr_code = "ABCDEFGH"[:t._QR_LENGTH]
t.store._exec("INSERT INTO magic_token(token_hash, purpose, created_at, expires_at, payload) VALUES (?,?,?,?,?)",
              (plain("qr:" + qr_code), "qr_login", now, now + 300, json.dumps({"device": plain("s"), "next": "/"})))
from starlette.requests import Request as _Request  # noqa: E402
_req = _Request({"type": "http", "method": "GET", "path": "/", "headers": [], "client": ("203.0.113.5", 1),
                 "query_string": b""})
real_qr = t._qr_start(_req)
t.store._exec("UPDATE magic_token SET payload=json_set(payload, '$.device', ?) WHERE purpose='qr_login' AND token_hash=?",
              (plain("chosen-secret"), token_peppered(tp, "magic", "qr:" + real_qr["code"])))
r.check("(e) QR: a planted code is no open request; a planted plain device secret is not the device's",
        t._qr_peek(qr_code) is None and t._qr_peek(real_qr["code"]) is not None
        and t._qr_own(real_qr["code"], "chosen-secret") is None)
# Every path that stores or looks up such a digest goes through the keyed digest (structure, so a new path cannot slip
# back to a plain sha256): the first argument of these store calls is built by `token_digest`/`_token_hash`/`_qr_hash`.
import ast as _ast  # noqa: E402
_CALLS = {"add_magic_token", "get_magic_token", "use_magic_token", "expire_magic_token", "approve_qr_token",
          "oauth_pair_service", "oauth_replace_consent_pairing", "get_api_key_by_hash", "add_api_key",
          "add_recovery_codes", "consume_recovery_code"}
#: The position of the digest argument where it is not the first (the others take it first).
_ARG_AT = {"add_api_key": 3, "add_recovery_codes": 1, "consume_recovery_code": 1}
_MARKS = ("token_digest", "_token_hash", "_qr_hash", "_rc_hash")
_plain_paths, _seen = [], 0
for _f in sorted((ROOT / "tinysesam").glob("*.py")):
    _tree = _ast.parse(_f.read_text(encoding="utf-8"))
    for _fn in _ast.walk(_tree):
        if not isinstance(_fn, (_ast.FunctionDef, _ast.AsyncFunctionDef)) or _f.name == "store.py":
            continue
        _assigned = {t.id: _ast.unparse(n.value) for n in _ast.walk(_fn) if isinstance(n, _ast.Assign)
                     for t in n.targets if isinstance(t, _ast.Name)}
        for _c in _ast.walk(_fn):
            if isinstance(_c, _ast.Call) and isinstance(_c.func, _ast.Attribute) and _c.func.attr in _CALLS:
                _at = _ARG_AT.get(_c.func.attr, 0)
                _arg = _c.args[_at] if len(_c.args) > _at else None
                _src = _ast.unparse(_arg) if _arg is not None else ""
                _src = _assigned.get(_src, _src)
                _seen += 1
                if not any(m in _src for m in _MARKS):
                    _plain_paths.append(f"{_f.name}:{_c.lineno} {_c.func.attr}({_src})")
r.check("(e) every store call that writes or looks up an API key, one-time token or recovery code digest gets the keyed "
        "digest", _seen >= 22 and not _plain_paths, f"{_seen} calls, plain: {_plain_paths}")
t.close()

# Pepper rotation: a key and a link from before stay valid; the key moves to the new pepper on its next use; `keys
# retire` refuses while an open link from before exists, and `--force` cuts it.
db_t = os.path.join(tempfile.mkdtemp(), "trot.db")
t1 = make(db_t)
t1uid = t1.create_user("tina", password="a long probe password 4711")
tok_old = t1.create_api_key(t1uid, name="ci")["key"]
tok_idle = t1.create_api_key(t1uid, name="idle")["key"]
old_link = t1.create_magic_token("login", user_id=t1uid, ttl_min=60)
t1.close()
time.sleep(1.1)       # `since` of the rotation must lie after `created_at` of the rows above
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "rotate", "--purpose", "oauth-pepper", "--db", db_t],
                     capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))
time.sleep(1.1)       # the use below lies after `since` (a use in the same second still counts as "before")
t2 = make(db_t)
new_p = t2._pepper_keyring.active.material
used = t2.verify_api_key(tok_old)[0] is not None
r.check("(e) after a pepper rotation the API key and the link from before stay valid; the key used once now carries "
        "the active pepper, the idle one still the old",
        out.returncode == 0 and used and t2.peek_magic(old_link) is not None
        and t2.store._one("SELECT 1 FROM api_key WHERE key_hash=?", (token_peppered(new_p, "apikey", tok_old),))
        and t2.store._one("SELECT 1 FROM api_key WHERE key_hash=?", (token_peppered(new_p, "apikey", tok_idle),)) is None,
        out.stderr[-300:])
t2.close()
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "retire", "--purpose", "oauth-pepper", "--db", db_t],
                     capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))
r.check("(e) `keys retire` refuses while an open link and an idle API key from before the rotation exist",
        out.returncode == 1 and "1 open one-time token(s)" in out.stderr and "1 API key(s)" in out.stderr,
        (out.stdout + out.stderr)[-400:])
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "retire", "--purpose", "oauth-pepper", "--force",
                      "--db", db_t], capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))
t3 = make(db_t)
r.check("(e) `--force` retires it: the link and the idle key are dead, the key used after the rotation lives on",
        out.returncode == 0 and t3.peek_magic(old_link) is None and t3.verify_api_key(tok_idle) == (None, None)
        and t3.verify_api_key(tok_old)[0] is not None, (out.stdout + out.stderr)[-300:])
t3.close()

# ---------------------------------------------------------------- (f) recovery codes (@344f94)
# Up to 0.30.0 a recovery code was stored as the plain sha256 of the normalised code: whoever could write the file put
# the digest of a code of their own choosing next to any account and held its second factor (a half session plus that
# code is a full one). Now an HMAC with the pepper, label `recovery`.
# (Mutation probes: `_rc_hash` back to a plain sha256 → the first two checks fall; drop the `recovery_codes_before`
# refusal in `keys retire` → the refusal check falls.)
f = make(os.path.join(tempfile.mkdtemp(), "rc.db"))
fuid = f.create_user("fred", password="a long probe password 4711")
fp = f._pepper_keyring.active.material
codes = f.generate_recovery_codes(fuid, n=3)
norm = codes[0].strip().lower().replace(" ", "")
r.check("(f) a recovery code is stored as the HMAC with the pepper, not as its sha256",
        f.store._one("SELECT 1 FROM recovery_code WHERE code_hash=?", (token_peppered(fp, "recovery", norm),)) is not None
        and f.store._one("SELECT 1 FROM recovery_code WHERE code_hash=?", (plain(norm),)) is None)
chosen_rc = "-".join(secrets.token_hex(7) for _ in range(2))
f.store._exec("INSERT INTO recovery_code(user_id, code_hash, created_at) VALUES (?, ?, ?)",
              (fuid, plain(chosen_rc), int(time.time())))
r.check("(f) a code planted as its plain sha256 is no second factor; a real code works once, typed in capitals too",
        f._verify_recovery_code(fuid, chosen_rc) is False and f._verify_recovery_code(fuid, codes[0].upper()) is True
        and f._verify_recovery_code(fuid, codes[0]) is False, "write access to the file mints a second factor")
f.close()

db_f = os.path.join(tempfile.mkdtemp(), "rcrot.db")
f1 = make(db_f)
f1uid = f1.create_user("fiona", password="a long probe password 4711")
old_codes = f1.generate_recovery_codes(f1uid, n=2)
f1.close()
time.sleep(1.1)       # `since` of the rotation lies after `created_at` of the codes
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "rotate", "--purpose", "oauth-pepper", "--db", db_f],
                     capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))
f2 = make(db_f)
r.check("(f) after a pepper rotation a recovery code from before still works (found with the previous pepper)",
        out.returncode == 0 and f2._verify_recovery_code(f1uid, old_codes[0]) is True, out.stderr[-300:])
f2.close()
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "retire", "--purpose", "oauth-pepper", "--db", db_f],
                     capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))
r.check("(f) `keys retire` refuses while an unused recovery code from before the rotation needs the old pepper",
        out.returncode == 1 and "1 unused recovery code(s)" in out.stderr, (out.stdout + out.stderr)[-400:])
time.sleep(1.1)       # the new codes lie after `since` (a code made in the same second still counts as before)
f3 = make(db_f)
fresh_codes = f3.generate_recovery_codes(f1uid, n=2)
f3.close()
out = subprocess.run([sys.executable, "-m", "tinysesam", "keys", "retire", "--purpose", "oauth-pepper", "--db", db_f],
                     capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT))
f4 = make(db_f)
r.check("(f) once the account generated new codes the retire goes through, and the new codes work",
        out.returncode == 0 and f4._verify_recovery_code(f1uid, fresh_codes[0]) is True
        and f4._verify_recovery_code(f1uid, old_codes[1]) is False, (out.stdout + out.stderr)[-400:])
f4.close()

sys.exit(r.done())
