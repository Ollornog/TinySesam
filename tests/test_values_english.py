"""Stored values in English (schema 12) — and the operator's lockout as a public method.

PO decision 2026-09-27, “translate everything, DB values too”: since 0.22.0 the values of the
public interface are also English, without alias. Two of them are in the database:

- `api_key.kind` — `automat`/`mensch` → `automation`/`human`;
- the payload of open address-change links (`magic_token`, `purpose='email_change'`) — `alt` → `old`.

The migration rewrites them at start (`Store._werte_englisch`, stamp 12), the code still reads an
old value correctly — an older version that ran on the same file after a rollback
has left old ones behind again — and writes only new ones. The way back to 0.21.x is stated as SQL in
`docs/OPERATIONS.md`; this suite runs exactly this block so that docs and effect do not
drift apart. What 0.21.0 itself does with a file at stamp 12 was measured once with the real
code from the tag (CHANGELOG 0.22.0) — not here, because the CI checkout has no tags.

In addition `auth.set_disabled(user_id, disabled)` (stage A): the same effect as the lockout in the panel,
which calls the method — up to 0.21.x the docs showed `auth.store.set_disabled(…, durch_betreiber=True)`,
which only set the mark.

All checks work without extras.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI                            # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

from tinysesam import TinySesam, TinySesamConfig               # noqa: E402
from tinysesam.errors import ConfigError, StateError           # noqa: E402
from tinysesam.store import Store                              # noqa: E402
from _kit.report import Report                                 # noqa: E402

r = Report("Werte englisch (Schema 12) und auth.set_disabled")

PW = "Probe-Pw-12345"
BASIS = "https://app.example.com"


def _aufbau(pfad: str, post: list | None = None) -> TinySesam:
    a = TinySesam(TinySesamConfig(db_path=pfad, cookie_secure=False, csrf_enabled=False,
                                  passkey_enabled=False, magiclink_enabled=True,
                                  signup_verify_email=True, base_url=BASIS))
    if post is not None:
        a.set_mailer(lambda to, betreff, text, html=None: post.append(text))
    return a


def _app(a: TinySesam) -> FastAPI:
    app = FastAPI()
    app.include_router(a.router())

    @app.get("/wer")
    def wer(u=Depends(a.require_user)):
        return {"user": u["username"], "via": u.get("_via"), "kind": u.get("_key_kind")}
    return app


def _mitschreiben(fn):
    """(result, text) — what the logger `tinysesam` says meanwhile, from INFO."""
    puffer = io.StringIO()
    haken = logging.StreamHandler(puffer)
    log = logging.getLogger("tinysesam")
    stufe = log.level
    log.addHandler(haken)
    log.setLevel(logging.INFO)
    try:
        ergebnis = fn()
    finally:
        log.removeHandler(haken)
        log.setLevel(stufe)
    return ergebnis, puffer.getvalue()


def _link(post: list) -> str:
    return next(m.group(1) for t in reversed(post)
                for m in [re.search(r"/auth/email/([A-Za-z0-9_\-]+)", t)] if m)


def _roh(pfad: str, *sql) -> None:
    """Write directly into the file like an older version (or the operator with `sqlite3`)."""
    con = sqlite3.connect(pfad)
    try:
        for s in sql:
            con.execute(*s) if isinstance(s, tuple) else con.executescript(s)
        con.commit()
    finally:
        con.close()


def _stand(pfad: str) -> tuple:
    """(stamp, key kinds, payloads of the address-change links) — raw from the file."""
    con = sqlite3.connect(pfad)
    try:
        return (con.execute("PRAGMA user_version").fetchone()[0],
                [z[0] for z in con.execute("SELECT kind FROM api_key ORDER BY id")],
                [json.loads(z[0]) for z in con.execute(
                    "SELECT payload FROM magic_token WHERE purpose='email_change' ORDER BY created_at, token_hash")])
    finally:
        con.close()


def _key_einfuegen(pfad: str, uid: int, kind: str) -> str:
    """Create a key the way 0.21.x issues it (`kind` as there) — returns the plaintext."""
    roh = "tsk_" + secrets.token_urlsafe(32)
    _roh(pfad, ("INSERT INTO api_key(user_id, name, prefix, key_hash, roles, kind, created_at, "
                "expires_at) VALUES (?,?,?,?,?,?,strftime('%s','now'),strftime('%s','now')+86400)",
                (uid, f"alt-{kind}", roh[:12] + "…", hashlib.sha256(roh.encode()).hexdigest(), "[]", kind)))
    return roh


def _link_einfuegen(pfad: str, uid: int, alt: str, neu: str) -> str:
    """Create an address-change link the way 0.21.x issues it (payload `{"alt": …}`)."""
    roh = secrets.token_urlsafe(32)
    _roh(pfad, ("INSERT INTO magic_token(token_hash, purpose, user_id, email, payload, created_at, "
                "expires_at) VALUES (?,?,?,?,?,strftime('%s','now'),strftime('%s','now')+3600)",
                (hashlib.sha256(roh.encode()).hexdigest(), "email_change", uid, neu,
                 json.dumps({"alt": alt}))))
    return roh


def _wirkung(a: TinySesam, mensch: str, automat: str) -> dict:
    """What the two keys do on a route: the human key alone and with a session, the
    automation key alone."""
    app = _app(a)
    ohne = TestClient(app)
    mit = TestClient(app)
    mit.post("/auth/login", data={"username": "anna", "password": PW}, follow_redirects=False)
    a_allein = ohne.get("/wer", headers={"X-API-Key": automat})
    return {"mensch_allein": ohne.get("/wer", headers={"X-API-Key": mensch}).status_code,
            "mensch_mit_sitzung": mit.get("/wer", headers={"X-API-Key": mensch}).status_code,
            "automat_allein": a_allein.status_code,
            "automat_kind": a_allein.json().get("kind") if a_allein.status_code == 200 else None}


# ── (a) A file from 0.21.x: the start migrates, the keys work as before ──────────────────────────
# (Mutation probes: remove the call of `_werte_englisch` in `_migrate` → (a) red, the kinds
# stay old; empty `KEY_ARTEN_ALT` → (a)/(b) red, `mensch` counts as an automation key and the key
# works without a session — exactly what 0.21.x does with a `human` key.)
pfad_a = os.path.join(tempfile.mkdtemp(), "a.db")
post_a: list = []
a = _aufbau(pfad_a, post_a)
anna = a.create_user("anna", password=PW, email="anna@example.com")
mensch_a = a.create_api_key(anna, name="cli", kind="human")["key"]
automat_a = a.create_api_key(anna, name="ci")["key"]
a.request_email_change(anna, "anna.neu@example.com", BASIS)()
link_a = _link(post_a)
a.store.db.close()
# This is how the file lay under 0.21.x: old values, stamp 11.
_roh(pfad_a, "UPDATE api_key SET kind='mensch' WHERE kind='human';"
             "UPDATE api_key SET kind='automat' WHERE kind='automation';"
             "UPDATE magic_token SET payload=json_object('alt', json_extract(payload, '$.old')) "
             "WHERE purpose='email_change';"
             "PRAGMA user_version = 11;")
vorher_a = _stand(pfad_a)
a, log_a = _mitschreiben(lambda: _aufbau(pfad_a, post_a))
nachher_a = _stand(pfad_a)
r.check("precondition: the file carries the values of 0.21.x and the stamp 11",
        vorher_a == (11, ["mensch", "automat"], [{"alt": "anna@example.com"}]), str(vorher_a))
r.check("(a) the start migrates: current stamp (from 12), `automation`/`human`, payload `old` — and says so in the log",
        nachher_a == (Store.SCHEMA_VERSION, ["human", "automation"], [{"old": "anna@example.com"}])
        and "3 gespeicherte Werte auf die englischen Namen umgeschrieben" in log_a,
        f"{nachher_a} {log_a[-300:]!r}")
w_a = _wirkung(a, mensch_a, automat_a)
r.check("(a) … the keys work as before: the human key only with a session, the automation key alone",
        w_a == {"mensch_allein": 401, "mensch_mit_sitzung": 200, "automat_allein": 200,
                "automat_kind": "automation"}, str(w_a))
r.check("(a) … `api_key_kind`, `list_api_keys` and the open link name the English values",
        a.api_key_kind(mensch_a) == "human" and a.api_key_kind(automat_a) == "automation"
        and sorted(k["kind"] for k in a.list_api_keys(anna)) == ["automation", "human"]
        and a.peek_magic(link_a, purpose="email_change")["payload"] == {"old": "anna@example.com"})
a.store.db.close()
a, log_a2 = _mitschreiben(lambda: _aufbau(pfad_a, post_a))
r.check("(a) second start: nothing left to rewrite (idempotent), same file",
        _stand(pfad_a) == nachher_a and "umgeschrieben" not in log_a2, log_a2[-300:])
r.check("(a) … and the link from 0.21.x redeems like any other",
        a.confirm_email_change(link_a) == "ok" and a.get_user(anna)["email"] == "anna.neu@example.com")
a.store.db.close()

# ── (a') Audit and log lines stay as they were ────────────────────────────────────────────────
# Operators' filters hang on them (PO decision 2026-09-27): the kind of a key still appears there
# as `art=automat`/`art=mensch`, the line in the security log names `'mensch'`.
# (Mutation probe: `_key_art_audit` returns the English name → (a') red.)
pfad_g = os.path.join(tempfile.mkdtemp(), "g.db")
g = _aufbau(pfad_g)
anna_g = g.create_user("anna", password=PW)
mensch_g = g.create_api_key(anna_g, name="cli", kind="human")
automat_g = g.create_api_key(anna_g, name="ci")
_sec = io.StringIO()
_sec_haken = logging.StreamHandler(_sec)
from tinysesam.security import seclog  # noqa: E402
seclog.addHandler(_sec_haken)
try:
    _cg = TestClient(_app(g))
    _cg.get("/wer", headers={"X-API-Key": automat_g["key"]})
    _cg.get("/wer", headers={"X-API-Key": mensch_g["key"]})
finally:
    seclog.removeHandler(_sec_haken)
_details = {f"{z['event']}:{m.group(1)}"
            for z in g.store._all("SELECT event, detail FROM audit WHERE event IN ('apikey_create', 'apikey_use')")
            for m in [re.search(r"(?:^| )art=(\S+)", z["detail"] or "")] if m}
r.check("(a') audit: `apikey_create`/`apikey_use` still name the kind with `art=automat|mensch`",
        {"apikey_create:mensch", "apikey_create:automat", "apikey_use:automat"} <= _details, str(_details))
r.check("(a') security log: the human key without a session is still called `'mensch'` there",
        "API-Key der Art 'mensch' ohne passende Sitzung" in _sec.getvalue(), _sec.getvalue()[-300:])
g.store.db.close()

# ── (b) Rollback: 0.21.x wrote old values again on the file (stamp 12) ─────────────────────────
# An older version does not lower the stamp. An old value is still read correctly, even
# without a restart (a second process still running 0.21.x); the next start rewrites the keys.
# The payload of a link only on the jump to 12 (the search would otherwise go through all
# one-time tokens at every start, tests/test_legacy_data.py “Aufwand”) — `peek_magic` maps it when reading.
# (Mutation probe: leave out the mapping in `TinySesam._key_kind` → (b) red: the `mensch` key
# works without a session.)
pfad_b = os.path.join(tempfile.mkdtemp(), "b.db")
b = _aufbau(pfad_b)
anna_b = b.create_user("anna", password=PW, email="anna@example.com")
neu_b = b.create_api_key(anna_b, name="neu", kind="human")["key"]
mensch_b = _key_einfuegen(pfad_b, anna_b, "mensch")
automat_b = _key_einfuegen(pfad_b, anna_b, "automat")
link_b = _link_einfuegen(pfad_b, anna_b, "anna@example.com", "anna.b@example.com")
r.check("precondition: mixed values at the current stamp (from 12)",
        _stand(pfad_b)[:2] == (Store.SCHEMA_VERSION, ["human", "mensch", "automat"]), str(_stand(pfad_b)))
w_b = _wirkung(b, mensch_b, automat_b)
# `list_api_keys` sorts by `created_at` (seconds) descending. The key from the library and
# the two inserted raw do not arise in the same second when the machine is busy
# (parallel suites) — then the newest came first, and the order check turned red
# although every kind was right. Therefore each key is checked by its name.
r.check("(b) mixed, without restart: `mensch` counts as `human` (only with a session), `automat` as "
        "`automation`",
        w_b == {"mensch_allein": 401, "mensch_mit_sitzung": 200, "automat_allein": 200,
                "automat_kind": "automation"}
        and [b.api_key_kind(k) for k in (neu_b, mensch_b, automat_b)] == ["human", "human", "automation"]
        and {k["name"]: k["kind"] for k in b.list_api_keys(anna_b)}
        == {"neu": "human", "alt-mensch": "human", "alt-automat": "automation"},
        f"{w_b} {[(k['name'], k['kind']) for k in b.list_api_keys(anna_b)]}")
r.check("(b) … the link from 0.21.x shows `old`, not `alt`",
        b.peek_magic(link_b, purpose="email_change")["payload"] == {"old": "anna@example.com"})
b.store.db.close()
b, log_b = _mitschreiben(lambda: _aufbau(pfad_b))
r.check("(b) the next start rewrites the keys (at every start), the link not (stamp already 12)",
        _stand(pfad_b) == (Store.SCHEMA_VERSION, ["human", "human", "automation"], [{"alt": "anna@example.com"}])
        and "2 gespeicherte Werte" in log_b, f"{_stand(pfad_b)} {log_b[-200:]!r}")
r.check("(b) … and it remains valid, redeemed with `old` in the result",
        b.redeem_magic(link_b, purpose="email_change")["payload"] == {"old": "anna@example.com"})
b.store.db.close()

# ── (c) The way back from docs/OPERATIONS.md: exactly the block that is stated there ──────────────
# (Mutation probe: remove the line for `mensch` in the SQL block of the docs → (c) red.)
_doku = (ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
_abschnitt = _doku.split("## Rückschritt auf 0.21.x", 1)[-1] if "## Rückschritt auf 0.21.x" in _doku else ""
_sql = re.search(r"```sql\n(.*?)```", _abschnitt, re.S)
r.check("docs/OPERATIONS.md has the section “Rollback to 0.21.x” with an SQL block",
        bool(_sql), "section or ```sql block missing")
if _sql:
    pfad_c = os.path.join(tempfile.mkdtemp(), "c.db")
    post_c: list = []
    c = _aufbau(pfad_c, post_c)
    anna_c = c.create_user("anna", password=PW, email="anna@example.com")
    c.create_api_key(anna_c, name="cli", kind="human")
    c.create_api_key(anna_c, name="ci")
    c.request_email_change(anna_c, "anna.c@example.com", BASIS)()
    c.store.db.close()
    _roh(pfad_c, _sql.group(1))
    r.check("(c) the SQL from the docs restores the values of 0.21.x and lowers the stamp to 11",
            _stand(pfad_c) == (11, ["mensch", "automat"], [{"alt": "anna@example.com"}]), str(_stand(pfad_c)))
    c = _aufbau(pfad_c, post_c)
    r.check("(c) … and a start of 0.22.0 afterwards migrates again (there and back without loss)",
            _stand(pfad_c) == (Store.SCHEMA_VERSION, ["human", "automation"], [{"old": "anna@example.com"}]), str(_stand(pfad_c)))
    c.store.db.close()

# ── (d) Read-only ─────────────────────────────────────────────────────────────────────────────
# Old values at stamp 12 (rollback) on a file without write permission: the start must not
# fail, which worked before — reading is correct anyway. An upgrade (stamp 11), on the other hand, needs
# write permission like any migration. The test makes it read-only itself, really via
# `PRAGMA query_only` (the other steps of the start write nothing that counts here).
# (Mutation probe: remove the `try` around `_werte_englisch` → (d) red, the start fails.)
_original = Store._werte_englisch


def _nur_lesbar(self, links=True):
    self.db.execute("PRAGMA query_only = ON")
    try:
        return _original(self, links)
    finally:
        self.db.execute("PRAGMA query_only = OFF")


pfad_d = os.path.join(tempfile.mkdtemp(), "d.db")
d = _aufbau(pfad_d)
anna_d = d.create_user("anna", password=PW)
d.store.db.close()
mensch_d = _key_einfuegen(pfad_d, anna_d, "mensch")
Store._werte_englisch = _nur_lesbar
try:
    try:
        d, log_d = _mitschreiben(lambda: _aufbau(pfad_d))
        start_d = "ok"
    except Exception as fehler:          # the start itself fails
        log_d, start_d = "", f"{type(fehler).__name__}: {fehler}"
    r.check("(d) read-only, stamp 12, old values: the start succeeds, says so, reads `mensch` as `human`",
            start_d == "ok" and "nicht auf die englischen Namen umgeschrieben" in log_d
            and d.api_key_kind(mensch_d) == "human" and _stand(pfad_d)[1] == ["mensch"],
            f"{start_d} {log_d[-200:]!r}")
    if start_d == "ok":
        d.store.db.close()
    _roh(pfad_d, "PRAGMA user_version = 11;")
    try:
        _aufbau(pfad_d).store.db.close()
        upgrade_d = "ok"
    except sqlite3.OperationalError as fehler:
        upgrade_d = f"OperationalError: {fehler}"
    r.check("(d) … an upgrade (stamp 11) without write permission aborts, like any migration",
            upgrade_d.startswith("OperationalError"), upgrade_d)
finally:
    Store._werte_englisch = _original

# ── (e) The old names are input errors whose text names the new ones — no alias ────────────────
pfad_e = os.path.join(tempfile.mkdtemp(), "e.db")
e = _aufbau(pfad_e)
bert = e.create_user("bert", password=PW)
_texte = {}
for alt_name, neu_name in (("automat", "automation"), ("mensch", "human")):
    try:
        e.create_api_key(bert, name="x", kind=alt_name)
        _texte[alt_name] = "angenommen"
    except ConfigError as fehler:
        _texte[alt_name] = str(fehler)
r.check("(e) `create_api_key(kind='automat'|'mensch')` → ConfigError that names the new name",
        all(f"heisst seit 0.22.0 {neu!r}" in _texte[alt] for alt, neu in
            (("automat", "automation"), ("mensch", "human"))), str(_texte))
_ce = TestClient(_app(e))
_ce.post("/auth/login", data={"username": "bert", "password": PW}, follow_redirects=False)
_antwort = _ce.post("/auth/apikeys", json={"name": "x", "kind": "mensch"})
_standard = _ce.post("/auth/apikeys", json={"name": "y"})
r.check("(e) … via `POST /auth/apikeys` 400 with the same hint; without `kind` an `automation` key",
        _antwort.status_code == 400 and "'human'" in _antwort.json()["detail"]
        and _standard.status_code == 200 and _standard.json()["kind"] == "automation"
        and "dropped_roles" in _standard.json(), f"{_antwort.text[:200]} {_standard.text[:200]}")
e.store.db.close()

# ── (f) auth.set_disabled: the operator's lockout with its full effect ─────────────────────────
# (Mutation probes, each individually: remove the ending of sessions in `set_disabled` → red; the
# revocation of the keys → red; `revoke_user_magic_tokens` → red; omit `durch_betreiber=True` → red
# (the confirmation link lifts the lockout); the audit line → red.)
pfad_f = os.path.join(tempfile.mkdtemp(), "f.db")
f = _aufbau(pfad_f)
ereignisse_f: list = []
f.on_security_event = lambda ereignis, konto, details: ereignisse_f.append((ereignis, details))
f.ensure_admin("chefin", PW)
chefin = f.find_user("chefin")["id"]
bert_f = f.create_user("bert", password=PW, email="bert@example.com")
app_f = _app(f)
cb = TestClient(app_f)
cb.post("/auth/login", data={"username": "bert", "password": PW}, follow_redirects=False)
key_f = f.create_api_key(bert_f, name="ci")["key"]
link_f = f.create_magic_token("login", user_id=bert_f, email="bert@example.com")
r.check("precondition: bert is signed in, his key works, his sign-in link is open",
        cb.get("/wer").status_code == 200 and f.verify_api_key(key_f)[0] is not None
        and f.peek_magic(link_f) is not None)
_vor = f.store._one("SELECT MAX(id) AS m FROM audit")["m"]
r.check("(f) `set_disabled(uid, True)` without a request → True", f.set_disabled(bert_f, True) is True)
_zeile = f.store._one("SELECT event, username, ip, detail FROM audit WHERE id > ? AND event='user_disable'",
                      (_vor,))
r.check("(f) … with operator mark, session ended, key revoked, link discarded",
        f.get_user(bert_f)["disabled"] == Store.GESPERRT_BETREIBER and cb.get("/wer").status_code == 401
        and f.verify_api_key(key_f) == (None, None) and f.peek_magic(link_f) is None
        and [k["revoked"] for k in f.list_api_keys(bert_f)] == [1])
r.check("(f) … audit `user_disable` under the affected account, event `api_keys_revoked` with `reason`",
        _zeile is not None and dict(_zeile) == {"event": "user_disable", "username": "bert", "ip": None,
                                                "detail": f"uid={bert_f} api_keys_revoked=1"}
        and ("api_keys_revoked", {"count": 1, "reason": "account_disabled"}) in ereignisse_f,
        f"{_zeile and dict(_zeile)} {ereignisse_f}")
_verify = f.create_magic_token("verify_email", user_id=bert_f, email="bert@example.com")
_v = TestClient(app_f).post(f"/auth/verify/{_verify}", follow_redirects=False)
r.check("(f) … a confirmation link that only arises afterwards does not lift the lockout (H-18)",
        _v.status_code == 403 and f.get_user(bert_f)["disabled"] == Store.GESPERRT_BETREIBER, str(_v.status_code))
r.check("(f) `set_disabled(uid, False)` unlocks; the revoked key stays revoked, the ended "
        "session stays ended (otherwise it would revive with the unlock)",
        f.set_disabled(bert_f, False) is True and f.get_user(bert_f)["disabled"] == 0
        and f.verify_api_key(key_f) == (None, None) and cb.get("/wer").status_code == 401
        and f.store.list_sessions(bert_f) == []
        and f.store._one("SELECT 1 FROM audit WHERE event='user_enable' AND username='bert' "
                         "AND detail=?", (f"uid={bert_f}",)) is not None)
_vor = f.store._one("SELECT MAX(id) AS m FROM audit")["m"]
try:
    f.set_disabled(chefin, True)
    _owner = "gesperrt"
except StateError:
    _owner = "StateError"
r.check("(f) an owner cannot be locked: StateError, and nothing happened",
        _owner == "StateError" and f.get_user(chefin)["disabled"] == 0
        and f.store._one("SELECT 1 FROM audit WHERE id > ?", (_vor,)) is None, _owner)
r.check("(f) an unknown account: False, no audit row",
        f.set_disabled(9999, True) is False
        and f.store._one("SELECT 1 FROM audit WHERE id > ?", (_vor,)) is None)

# The panel calls exactly this method — and writes the same line as up to 0.21.x: the admin as
# Konto, seine IP, `uid=… api_keys_revoked=…`.
ca = TestClient(app_f)
ca.post("/auth/login", data={"username": "chefin", "password": PW}, follow_redirects=False)
f.create_api_key(bert_f, name="zwei")
_vor = f.store._one("SELECT MAX(id) AS m FROM audit")["m"]
_p = ca.post(f"/auth/admin/api/users/{bert_f}/disable", json={"disabled": True})
_zeile = f.store._one("SELECT event, username, ip, detail FROM audit WHERE id > ? AND event='user_disable'",
                      (_vor,))
r.check("(f) panel: 200, same effect, audit under the admin with his IP (as up to 0.21.x)",
        _p.status_code == 200 and f.get_user(bert_f)["disabled"] == Store.GESPERRT_BETREIBER
        and _zeile is not None and dict(_zeile) == {"event": "user_disable", "username": "chefin",
                                                    "ip": "testclient",
                                                    "detail": f"uid={bert_f} api_keys_revoked=1"},
        f"{_p.status_code} {_zeile and dict(_zeile)}")
r.check("(f) panel: an unknown account → 404 instead of 200 (up to 0.21.x “ok” and an audit row)",
        ca.post("/auth/admin/api/users/9999/disable", json={"disabled": True}).status_code == 404)
f.store.db.close()

# One source: the panel route calls `auth.set_disabled` and none of the steps itself.
_admin = ast.parse((ROOT / "tinysesam" / "admin.py").read_text(encoding="utf-8"))
_route = next(k for k in ast.walk(_admin) if isinstance(k, ast.AsyncFunctionDef) and k.name == "user_disable")
_rufe = {ast.unparse(k.func) for k in ast.walk(_route) if isinstance(k, ast.Call)}
_ueberall = {ast.unparse(k.func) for k in ast.walk(_admin) if isinstance(k, ast.Call)}
r.check("(f) one source: `user_disable` calls `auth.set_disabled`, no step itself; admin.py calls "
        "`store.set_disabled` nowhere",
        "auth.set_disabled" in _rufe
        and not _rufe & {"auth.store.set_disabled", "auth.store.delete_user_sessions", "auth._keys_widerrufen",
                         "auth.store.revoke_user_magic_tokens", "protokoll"}
        and "auth.store.set_disabled" not in _ueberall, str(sorted(_rufe)))

raise SystemExit(r.done())
