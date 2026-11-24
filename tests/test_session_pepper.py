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

    python tests/run_all.py test_session_pepper.py
"""
import hashlib
import hmac
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
r.check("(d) a store without the pepper refuses to digest a session token (no silent sha256)", refused)
bare.close()

sys.exit(r.done())
