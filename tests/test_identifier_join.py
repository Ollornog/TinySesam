"""Limit a in full: an identifier belongs to the account from its JOINING, not from creation (G2).

Limit a from the integration attack fixed the creation of the account as the limit: failed attempts and
audit rows from before do not belong to the account. But an account also gets name and address later
— on rename, on address change, on the addition of an address. Until 2026-09-26 the first
full sign-in afterwards cleared the failed attempts that a stranger had made earlier under the then free identifier,
also from the throttling of his IP; the account page showed the sign-in of the
previous owner including his IP, and deleting rewrote his rows. The limit is now an
id watermark per identifier (`users.name_attempt_from` …): exact even in the second of joining.

a  rename              f  deleting after the rename
b  address change      g  account page and audit after takeover of a free name
c  second of creation  h  existing data without watermark: as before (creation)
d  own failed attempts i  foreign writer (raw SQL): watermark to the current state
e  spelling only       j  the series (B2-6) is deliberately cleared completely
                       i  also one that carries the bucket itself (0.20.1, review round 2026-09-27)
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.store import SCHEMA, Store  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Joining an identifier — limit a for renaming, address change, deletion")
PW = "Join-Test-7xxxx"
BASE = "http://testserver"
SPRAYER, OWN = "203.0.113.9", "198.51.100.30"


def _app(db_path=None, **cfg):
    post: list = []
    reason = dict(db_path=db_path or str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, passkey_enabled=False, base_url=BASE, lang="de")
    reason.update(cfg)
    auth = TinySesam(TinySesamConfig(**reason))
    auth.set_mailer(lambda to, subject, text, html=None: post.append((to, subject, text)))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, post


def _login(app, name, ip="testclient"):
    return TestClient(app, client=(ip, 1)).post("/auth/login", data={"username": name, "password": PW},
                                                follow_redirects=False)


def _failed_attempts(auth, identifier, ip, n, before=0):
    """`n` failed attempts under `kennung` from `ip` — via the path of the routes (with pre-booking of the
    series) —, dated `before` seconds back."""
    for _ in range(n):
        v = auth._begin_attempt(identifier, ip, "password")
        auth._record_login(identifier, ip, False, "password", attempt=v)
    if before:
        auth.store._exec("UPDATE login_attempt SET ts = ts - ? WHERE ip = ?", (before, ip))


def _line(auth, uid):
    return auth.store.get_user(uid)


# ── a: Renaming────────────────────────────────────────────────────────────────────────────────
# (Mutation probes: in `lift_lockout` only `seit` instead of `from_id` → red; in `_cleanup_limit` always
#  without limit (`{}`) → red: the sign-in under `free` then already clears at the first factor.)
a, app, _ = _app()
uid = a.create_user("alt", password=PW)
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_failed_attempts(a, "free", SPRAYER, 3, before=3600)
a.change_username(uid, "free")
note = _login(app, "free")
r.check("a: rename — the failed attempts of a stranger under the then free name remain "
        "after the full sign-in",
        note.status_code == 303 and a.store.count_fails(0, username="free") == 3,
        f"HTTP {note.status_code}, {a.store.count_fails(0, username='free')}")
r.check("… also in the throttling of HIS IP", a.store.count_fails(0, ip=SPRAYER) == 3,
        str(a.store.count_fails(0, ip=SPRAYER)))
_failed_attempts(a, "free", OWN, 2)
_login(app, "free")
r.check("… the own ones after the rename are cleared by the sign-in as before",
        a.store.count_fails(0, ip=OWN) == 0 and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"{a.store.count_fails(0, ip=OWN)} / {a.store.count_fails(0, ip=SPRAYER)}")

# ── b: address change via the real link, and the addition of an address (OIDC) ───────────────
# (Mutation probe: do not set the watermarks in `_set_identifier` → both red.)
a, app, post = _app()
uid = a.create_user("mia", password=PW, email="mia@example.com")
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_failed_attempts(a, "new@example.com", SPRAYER, 2, before=3600)
a.request_email_change(uid, "new@example.com", BASE)()
a._notice_outcome.wait()
link = next((t.group(1) for destination, _b, text in post if destination == "new@example.com"
             for t in [re.search(re.escape(BASE) + r"(/auth/email/\S+)", text)] if t), "")
confirmed = TestClient(app).post(link, follow_redirects=False) if link else None
note = _login(app, "new@example.com")
r.check("b: address change via the link — the failed attempts under the new address from before remain",
        confirmed is not None and confirmed.status_code == 303 and a.get_user(uid)["email"] == "new@example.com"
        and note.status_code == 303 and a.store.count_fails(0, username="new@example.com") == 2,
        f"Link {bool(link)}, HTTP {note.status_code}, {a.store.count_fails(0, username='new@example.com')}")
_failed_attempts(a, "addendum@example.com", "203.0.113.10", 2, before=3600)
a.store.set_email(uid, "addendum@example.com", verified=True)      # the path of the OIDC addition
_login(app, "mia")
r.check("… likewise on the addition of an address (store.set_email, the path of OIDC)",
        a.store.count_fails(0, username="addendum@example.com") == 2,
        str(a.store.count_fails(0, username="addendum@example.com")))

# ── c: the second of creation ─────────────────────────────────────────────────────────────────
# A timestamp cannot decide whether an attempt of the same second came before or after the creation;
# the id can. (Mutation probe: `identifier_limits` always returns None → fallback to the
# creation with `ts >= seit` → red.)
a, app, _ = _app()
_failed_attempts(a, "sec@example.com", SPRAYER, 1)
uid = a.create_user("sec", password=PW, email="sec@example.com")
a.store._exec("UPDATE login_attempt SET ts = (SELECT created_at FROM users WHERE id = ?) WHERE ip = ?",
              (uid, SPRAYER))
note = _login(app, "sec@example.com")
r.check("c: a foreign failed attempt from the second of creation, but BEFORE it, remains",
        note.status_code == 303 and a.store.count_fails(0, username="sec@example.com") == 1,
        f"HTTP {note.status_code}, {a.store.count_fails(0, username='sec@example.com')}")

# ── d: counter-check — no overcorrection ──────────────────────────────────────────────────────
# (Mutation probe: watermark + 1 in `WL_ATTEMPT` → red; that also keeps out a time-dependent version
#  with `ts > seit`, which would leave own attempts of the same second standing.)
a, app, _ = _app()
a.create_user("immediately", password=PW, email="immediately@example.com")
_failed_attempts(a, "immediately", OWN, 1)
_failed_attempts(a, "immediately@example.com", OWN, 1)
note = _login(app, "immediately")
r.check("d: own failed attempts directly after creation (same second) are cleared by the full sign-in",
        note.status_code == 303 and a.store.count_fails(0, ip=OWN) == 0, str(a.store.count_fails(0, ip=OWN)))

# ── e: only the spelling changed ──────────────────────────────────────────────────────────────
# The same identifier in the counting bucket — the limit stays. The recalculation trigger cannot tell an own
# writer from a foreign one; `_set_identifier` makes sure it does not
# fire here. (Mutation probes: leave out the CASE for the watermark → red; leave the bucket in the first
# statement instead of NULL → the trigger fires and raises the watermark → red.)
a, app, _ = _app()
uid = a.create_user("Gross", password=PW, email="gross@example.com")
before = _line(a, uid)
_failed_attempts(a, "someone-different", SPRAYER, 2)
a.store.audit_log("probe", "someone-different")
a.change_username(uid, "gross")
a.store.set_email(uid, "GROSS@example.com", verified=True)
afterwards = _line(a, uid)
_columns = ("name_attempt_from", "name_audit_from", "mail_attempt_from", "mail_audit_from")
r.check("e: renaming only in upper/lower case (name and address) moves no watermark",
        all(before[s] is not None and before[s] == afterwards[s] for s in _columns)
        and afterwards["username"] == "gross" and afterwards["folded_name"] == "gross"
        and afterwards["folded_mail"] == "gross@example.com",
        f"{[before[s] for s in _columns]} → {[afterwards[s] for s in _columns]}, Bucket {afterwards['folded_name']!r}")
a.change_username(uid, "gross-new")
new_z = _line(a, uid)
r.check("… a new name sets it to the current state",
        new_z["name_attempt_from"] == a.store._one("SELECT MAX(id) AS m FROM login_attempt")["m"]
        and new_z["name_audit_from"] is not None and new_z["name_audit_from"] > before["name_audit_from"]
        and new_z["mail_attempt_from"] == before["mail_attempt_from"],
        str(dict(new_z)))

# ── f: deleting after the rename ─────────────────────────────────────────────────────────────
# (Mutation probe: `remove_account` passes no `from_ids` to `delete_attempts_for` → red.)
a, app, _ = _app()
uid = a.create_user("fx", password=PW)
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_failed_attempts(a, "fneu", SPRAYER, 2, before=3600)
a.change_username(uid, "fneu")
_failed_attempts(a, "fneu", OWN, 2)
a.delete_user(uid)
r.check("f: deleting after the rename — the stranger's attempts under the new name remain, "
        "the own ones go",
        a.store.count_fails(0, ip=SPRAYER) == 2 and a.store.count_fails(0, ip=OWN) == 0,
        f"{a.store.count_fails(0, ip=SPRAYER)} / {a.store.count_fails(0, ip=OWN)}")

# ── g: takeover of a freed name — account page and audit ─────────────────────────────────────
# (Mutation probes: `own_events` only with `setup_limit` → red; `remove_account` passes no
#  `from_ids` an `anonymize_audit` → rot.)
a, app, _ = _app()
b = a.create_user("bert", password=PW)
a.store._exec("UPDATE users SET created_at = created_at - 100 WHERE id = ?", (b,))
x = a.create_user("xaver", password=PW)
_login(app, "xaver", ip="198.51.100.77")
a.change_username(x, "xaver-new")
a.change_username(b, "xaver")
own = a.own_events(b)
r.check("g: whoever takes over a free name does not see the sign-in of the "
        "previous owner (including his IP) on the account page",
        not any(e["ip"] == "198.51.100.77" or e["event"] == "login" for e in own)
        and any(e["event"] == "username_changed" for e in own), str(own))
a.delete_user(b)
r.check("… and his deleting does not rewrite the previous owner's rows",
        a.store._one("SELECT username FROM audit WHERE event='login' AND ip='198.51.100.77'")["username"] == "xaver",
        str([dict(z) for z in a.store._all("SELECT event, username, ip FROM audit")]))

# ── h: existing data without watermark ───────────────────────────────────────────────────────
# A file from before this column (schema 11 without it; the later
# `name_self_chosen`, G2-N, behind it is recorded along): the columns are added and stay NULL,
# the limit is then the creation as before. (Mutation probes: the fallback in `lift_lockout`
# clears from id 0 instead of from the creation → red; likewise in `_cleanup_limit` → red.)
_inventory = str(Path(tempfile.mkdtemp()) / "t.db")
_old_schema, _n_users = re.subn(r"(idp_confirmed_at INTEGER), (--[^\n]*)\n\s*-- From when does the identifier belong.*?"
                                r"mail_audit_from\s+INTEGER,\n.*?name_self_chosen INTEGER NOT NULL DEFAULT 0\n",
                                r"\1  \2\n", SCHEMA, flags=re.S)
_old_schema, _n_fi = re.subn(r"\n\s*-- The name under which the account last signed in.*?directory_name_folded\s+TEXT,", "",
                             _old_schema, flags=re.S)
os.close(os.open(_inventory, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
_raw = sqlite3.connect(_inventory)
_raw.executescript(_old_schema)
_now = int(time.time())
_raw.execute("INSERT INTO users(username, email, created_at) VALUES ('existing', 'existing@example.com', ?)",
             (_now - 1800,))
_raw.executemany("INSERT INTO login_attempt(ts, username, ip, success, method) VALUES (?, ?, ?, 0, 'password')",
                 [(_now - 3600, "existing@example.com", SPRAYER)] * 3
                 + [(_now - 60, "existing@example.com", OWN)] * 2)
_raw.execute(f"PRAGMA user_version = {Store.SCHEMA_VERSION}")
_raw.commit()
_raw.close()
a, app, _ = _app(db_path=_inventory)
_uid = a.store.get_user_by_name("existing")["id"]
a.set_password(_uid, PW)
_hb = _line(a, _uid)
_fi = {z["name"] for z in a.store.db.execute("PRAGMA table_info(federated_identity)")}
r.check("h: existing data — the columns are added and stay NULL (no limit invented)",
        _n_users == 1 and _n_fi == 1 and all(_hb[s] is None for s in _columns) and "directory_name_folded" in _fi,
        f"cut {_n_users}/{_n_fi}, {[_hb[s] for s in _columns]}, {_fi}")
note = _login(app, "existing@example.com")
r.check("… limit is then the creation as before: foreign data from before remains, own data goes",
        note.status_code == 303 and a.store.count_fails(0, ip=SPRAYER) == 3 and a.store.count_fails(0, ip=OWN) == 0,
        f"HTTP {note.status_code}, {a.store.count_fails(0, ip=SPRAYER)} / {a.store.count_fails(0, ip=OWN)}")
a2, _, _ = _app(db_path=_inventory)
_second = _line(a2, _uid)
_trigger = a2.store._all("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'trg_users_folded_%'")
r.check("… a second start changes nothing (idempotent, trigger once each)",
        all(_second[s] is None for s in _columns) and len(_trigger) == 2, f"{dict(_second)} {len(_trigger)}")

# ── i: a foreign writer (raw SQL, older version) ──────────────────────────────────────────────
# The recalculation trigger raises the watermarks — the stricter direction. (Mutation probe: the
# trigger in the version of G12c, only `topf = NULL` → red.)
a, app, _ = _app()
uid = a.create_user("raw-alt", password=PW, email="raw@example.com")
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_failed_attempts(a, "raw-new", SPRAYER, 3, before=3600)
a.store.audit_log("probe", "raw-new")
a.store._exec("UPDATE users SET username = 'raw-new' WHERE id = ?", (uid,))
a.store._exec("UPDATE users SET email = 'raw2@example.com' WHERE id = ?", (uid,))
_ri = _line(a, uid)
_max_v = a.store._one("SELECT MAX(id) AS m FROM login_attempt")["m"]
_max_a = a.store._one("SELECT MAX(id) AS m FROM audit")["m"]
r.check("i: raw UPDATE of name and address → watermarks at the current state, bucket recalculated",
        _ri["name_attempt_from"] == _max_v == _ri["mail_attempt_from"] and _ri["name_audit_from"] == _max_a
        and _ri["mail_audit_from"] == _max_a and _ri["folded_name"] is None and _ri["folded_mail"] is None,
        f"{dict(_ri)} MAX {_max_v}/{_max_a}")
note = _login(app, "raw-new")
r.check("… and the sign-in under the new name leaves the attempts from before standing",
        note.status_code == 303 and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"HTTP {note.status_code}, {a.store.count_fails(0, ip=SPRAYER)}")

# A foreign writer that carries the bucket ITSELF — `store.set_email` from 0.20.1 sets address and
# `folded_mail` in ONE statement (review round 2026-09-27, p1-c). The recalculation trigger then does
# not fire (the bucket does change), and until then the watermark stayed at the state of the OLD
# address: the first full sign-in cleared the stranger's failed attempts under the new one, also from
# the throttling of his IP. (Mutation probe: leave out `trg_users_change_mail` → red.)
from tinysesam.store import norm_email, norm_identifier  # noqa: E402

a, app, _ = _app()
uid = a.create_user("mia", password=PW, email="mia@example.com")
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_failed_attempts(a, "new@example.com", SPRAYER, 3, before=3600)
_wl_c = _line(a, uid)["mail_attempt_from"]
_new_c = norm_email("new@example.com")
a.store._exec("UPDATE users SET email=?, email_verified=?, folded_mail=? WHERE id=?",
              (_new_c, 1, norm_identifier(_new_c), uid))
_rc = _line(a, uid)
note = _login(app, "new@example.com")
r.check("i: the writer from 0.20.1 (address and bucket in one statement) raises the watermark too — "
        "the failed attempts under the new address remain",
        _rc["mail_attempt_from"] == a.store._one("SELECT MAX(id) AS m FROM login_attempt")["m"] > _wl_c
        and _rc["folded_mail"] == "new@example.com" and note.status_code == 303
        and a.store.count_fails(0, username="new@example.com") == 3 and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"WL {_wl_c} → {_rc['mail_attempt_from']}, HTTP {note.status_code}, {a.store.count_fails(0, ip=SPRAYER)}")
# Counter-checks: the addition (only the bucket, NULL → bucket) and the own rewrite `B1` → `b1` (the same
# bucket) move nothing.
_prior_n = (_rc["name_attempt_from"], _rc["mail_attempt_from"])
_failed_attempts(a, "elsewhere", SPRAYER, 1)                 # otherwise the high-water mark would already stand there
a.store._exec("UPDATE users SET folded_name = NULL WHERE id = ?", (uid,))
a.store._exec("UPDATE users SET folded_name = ? WHERE id = ?", ("mia", uid))
a.store.set_username(uid, "MIA")
_rn = _line(a, uid)
r.check("… the addition of a bucket and `mia` → `MIA` (the same bucket) leave the watermarks standing",
        (_rn["name_attempt_from"], _rn["mail_attempt_from"]) == _prior_n and _rn["folded_name"] == "mia",
        f"{_prior_n} → {(_rn['name_attempt_from'], _rn['mail_attempt_from'])}")

# ── j: the series (B2-6) ─────────────────────────────────────────────────────────────────────
# Deliberately WITHOUT limit a (reasoning in `lift_lockout`): the series has no IP, and before the
# join it protected no account. A limit in time would leave a series begun before the join
# unendable for the new owner. (Mutation probe: `delete_failure_series(…, kinds=())` → red.)
a, app, _ = _app()
_failed_attempts(a, "series@example.com", SPRAYER, 3, before=3600)
uid = a.create_user("serienkonto", password=PW, email="series@example.com")
series_before = a.store.failure_series("series@example.com")
_login(app, "serienkonto")
r.check("j: the series under the address from before creation ends with the first full sign-in",
        series_before == 3 and a.store.failure_series("series@example.com") == 0
        and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"{series_before} → {a.store.failure_series('series@example.com')}, Window {a.store.count_fails(0, ip=SPRAYER)}")

sys.exit(r.done())
