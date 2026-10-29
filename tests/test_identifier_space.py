"""Identifier space: username and address are ONE space — enforced by the database (G12c).

`find_user` searches in both columns, and the counting bucket (`norm_identifier`) folds more coarsely than NOCASE.
Until 2026-09-26 only `identifier_taken` checked that BEFORE writing; the database knew
`UNIQUE(username)` (BINARY) and `ux_users_email`. Two simultaneous requests for the same identifier —
one as name, one as address — both got through, or one ended with a 500. What is measured:

A  the store itself rejects every new collision and lets the intended through;
B  the race, deterministic: a second instance on the same file creates AFTER the
   first has checked and BEFORE it writes — every path answers in substance, never with a 500;
C  the same for real in parallel;
D  existing data with collisions: start, complete message, resolvable;
E  the address change in mail mode is one transaction;
F  a file on which the triggers cannot be created starts anyway;
G  the check does not cost more with the number of accounts (SQLite steps).
"""
from __future__ import annotations

import html
import io
import logging
import re
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.store import Store, now  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Identifier space — name and address, enforced by the database")
PW = "Identifier-Test-15"
BASE = "http://testserver"
GRANT = Store.IDENTIFIER_GRANT


def _file() -> str:
    return str(Path(tempfile.mkdtemp()) / "t.db")


def _rejected(fn) -> str:
    """“durch”, or the text of the IntegrityError with which the database rejects."""
    try:
        fn()
    except sqlite3.IntegrityError as e:
        return str(e)
    return "by"


def _raw(store, name, mail=None) -> int:
    """An account via raw INSERT without bucket — the path of a foreign writer (older version,
    sqlite3 tool) which the identifier triggers do not see."""
    return store._exec("INSERT INTO users(username, display_name, email, created_at) VALUES (?,?,?,?)",
                       (name, name, mail, now())).lastrowid


def _pair(**cfg):
    """Two instances on the SAME file — two workers (`uvicorn --workers 2`)."""
    reason = dict(db_path=_file(), cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
                 base_url=BASE, lang="de")
    reason.update(cfg)
    a = TinySesam(TinySesamConfig(**reason))
    b = TinySesam(TinySesamConfig(**reason))
    app = FastAPI()
    app.include_router(a.router())
    return a, b, app


def _between(auth, method, before, afterwards=None):
    """Once: `before()` (the simultaneous request of the OTHER instance) runs AFTER `auth`
    has passed all checks and BEFORE its store writes. `afterwards()` runs directly after
    the write (even if it fails) — before the manager sees the error. A hook
    that no request has triggered is replaced, not nested."""
    auth.store.__dict__.pop(method, None)
    original = getattr(auth.store, method)

    def check(*a, **k):
        auth.store.__dict__.pop(method, None)
        before()
        try:
            return original(*a, **k)
        finally:
            if afterwards:
                afterwards()
    setattr(auth.store, method, check)


def _record(logger_name: str, fn):
    buffer = io.StringIO()
    check = logging.StreamHandler(buffer)
    log = logging.getLogger(logger_name)
    log.addHandler(check)
    try:
        result = fn()
    finally:
        log.removeHandler(check)
    return result, buffer.getvalue()


def _audit(auth, event):
    z = auth.store._one("SELECT detail FROM audit WHERE event=? ORDER BY id DESC LIMIT 1", (event,))
    return z["detail"] if z else None


def _link(post, an):
    for destination, text in post:
        t = re.search(re.escape(BASE) + r"(/auth/email/\S+)", text)
        if destination == an and t:
            return t.group(1)
    return ""


# ── A: the store rejects every new collision ──────────────────────────────────────────────────
# (Mutation probes: do not create the INSERT trigger → red; do not create the UPDATE trigger → red;
#  remove `id IS NOT NEW.id` → red on the change in mail mode; remove the second statement in
#  `_set_identifier` that resets the bucket → red on “B1 → b1".)
s = Store(_file())
blocked = {}
s.create_user("Alice")
blocked["Alice / alice"] = _rejected(lambda: s.create_user("alice"))
s.create_user("Émile")
blocked["Émile / émile"] = _rejected(lambda: s.create_user("émile"))
s.create_user("ｂｏｂ")
blocked["ｂｏｂ (full-width) / bob"] = _rejected(lambda: s.create_user("bob"))
s.create_user("k1", email="x@example.com")
blocked["name = foreign address"] = _rejected(lambda: s.create_user("X@example.com"))
s.create_user("q@example.com")
blocked["address = foreign name"] = _rejected(lambda: s.create_user("q2", email="q@example.com"))
s.create_user("u1", email="u@bücher.example")
blocked["address in A-label form"] = _rejected(lambda: s.create_user("u2", email="u@xn--bcher-kva.example"))
a_id, b_id = s.create_user("a1"), s.create_user("b1")
s.set_email(a_id, "free@example.com")
blocked["set_email → foreign address"] = _rejected(lambda: s.set_email(b_id, "FREE@example.com"))
blocked["set_email → foreign name"] = _rejected(lambda: s.set_email(b_id, "q@example.com"))
blocked["set_username → foreign address"] = _rejected(lambda: s.set_username(b_id, "x@example.com"))
blocked["set_username → namesake"] = _rejected(lambda: s.set_username(b_id, "ALICE"))
r.check("A: the database rejects every new collision in the identifier space (IntegrityError)",
        set(blocked.values()) == {GRANT}, str(blocked))
_b = s.get_user(b_id)
r.check("A: … nothing changes in the process, and no transaction stays open",
        _b["username"] == "b1" and not _b["email"] and not s.db.in_transaction
        and len(s._all("SELECT id FROM users")) == 8, f"{dict(_b)} open={s.db.in_transaction}")
through = {}
through["name = own address (email mode)"] = _rejected(
    lambda: s.create_user("solo@example.com", email="solo@example.com"))
through["set the same address again"] = _rejected(lambda: s.set_email(a_id, "free@example.com", verified=True))
through["b1 → B1 (own bucket)"] = _rejected(lambda: s.set_username(b_id, "B1"))
_e = s.create_user("em@example.com", email="em@example.com")
through["mail mode: change address and name"] = _rejected(
    lambda: s.address_switch(_e, "em2@example.com", name_follows=True))
through["the old address is free afterwards"] = _rejected(lambda: s.create_user("em@example.com"))
r.check("A: … these pass: name = own address, the same address again, a name in the own bucket, "
        "the change in mail mode", set(through.values()) == {"by"}, str(through))
_pots = tuple(s._one("SELECT folded_name, folded_mail FROM users WHERE id=?", (b_id,)))
r.check("A: … “B1” keeps its bucket (the recalculation trigger otherwise sets it to NULL), “b1” stays taken",
        _pots == ("b1", "") and _rejected(lambda: s.create_user("b1")) == GRANT, str(_pots))
# A foreign writer that sets the same value again does not take the bucket from the account (until
# 2026-09-26 it stood at NULL afterwards until the next addition, and the triggers did not see the
# account). (Mutation probe: remove `NEW.<column> IS NOT OLD.<column>` in the recalculation trigger → red.)
s._exec("UPDATE users SET username=username, email=email WHERE id=?", (a_id,))
r.check("A: … an UPDATE to the same value leaves the bucket standing",
        tuple(s._one("SELECT folded_name, folded_mail FROM users WHERE id=?", (a_id,))) == ("a1", "free@example.com"))
# A trigger from schema 10 (the version of 0.20.1) is replaced by today's — with
# `IF NOT EXISTS` alone it would stand there forever. (Mutation probe: leave every existing trigger standing
# lassen → rot.)
_old_db = _file()
_old = Store(_old_db)
_old._exec("DROP TRIGGER trg_users_folded_name")
_old._exec("CREATE TRIGGER trg_users_folded_name AFTER UPDATE OF username ON users WHEN NEW.folded_name "
           "IS OLD.folded_name BEGIN UPDATE users SET folded_name = NULL WHERE id = NEW.id; END")
_old.db.close()
_new = Store(_old_db)
_sql = _new._one("SELECT sql FROM sqlite_master WHERE name='trg_users_folded_name'")["sql"]
r.check("A: a trigger from an older version is replaced at start",
        "NEW.username IS NOT OLD.username" in _sql, _sql)

# ── B: race, deterministic─────────────────────────────────────────────────────────────────
# (Mutation probes: remove the mapping of the IntegrityError in `create_user`, `confirm_email_change`,
#  `change_username`, in the OIDC addition, in `_address_proven_by_source` and in the routes
#  `register`/admin → each red, mostly with a 500.)
a, b, _ = _pair()
_between(a, "create_user", lambda: b.create_user("rb", password=PW, email="race@example.com"))
try:
    a.create_user("race@example.com", password=PW)
    b1 = None
except ConfigError as error:
    b1 = (error.field, error.owner_id)
r.check("B1: name against a simultaneously created address → ConfigError, field and owner correct",
        b1 == ("username", b.store.get_user_by_name("rb")["id"]), str(b1))
_between(a, "create_user", lambda: b.create_user("race2@example.com", password=PW))
try:
    a.create_user("rc", password=PW, email="race2@example.com")
    b1b = None
except ConfigError as error:
    b1b = (error.field, error.owner_id)
r.check("B1: … address against a simultaneously created name → field “email”",
        b1b == ("email", b.store.get_user_by_name("race2@example.com")["id"]), str(b1b))
_between(a, "create_user", lambda: b.create_user("path", password=PW),
            afterwards=lambda: b.delete_user(b.store.get_user_by_name("path")["id"]))
try:
    a.create_user("PATH", password=PW)
    b1c = None
except ConfigError as error:
    b1c = (error.field, error.owner_id, str(error))
r.check("B1: … if the other account is already gone again: ConfigError without owner, not IntegrityError",
        b1c == ("username", None, "username is already taken"), str(b1c))
r.check("B1: … no collision in the database", a.store.bucket_collisions() == [], str(a.store.bucket_collisions()))

# B2: address change against a registration with name = address.
a, b, app_a = _pair()
post: list = []
a.set_mailer(lambda to, subject, text, html=None: post.append((to, text)))
carla = a.create_user("carla", password=PW, email="carla@example.com")
a.request_email_change(carla, "new@example.com", BASE)()
_between(a, "address_switch", lambda: b.create_user("new@example.com", password=PW))
b2 = TestClient(app_a, raise_server_exceptions=False).post(_link(post, "new@example.com"), follow_redirects=False)
r.check("B2: confirm_email_change in a race → 409, the address stays, audit row with race=1",
        b2.status_code == 409 and a.get_user(carla)["email"] == "carla@example.com"
        and "race=1" in (_audit(a, "email_change_taken") or "") and a.store.bucket_collisions() == [],
        f"HTTP {b2.status_code}, {a.get_user(carla)['email']}, {_audit(a, 'email_change_taken')}")

# B3: rename on the account page.
a, b, app_a = _pair()
dora = a.create_user("dora", password=PW)
c = TestClient(app_a, raise_server_exceptions=False)
c.post("/auth/login", data={"username": "dora", "password": PW}, follow_redirects=False)
_between(a, "set_username", lambda: b.create_user("Zeta", password=PW))
b3 = c.post("/auth/account/username", json={"username": "zeta"})
r.check("B3: change_username in a race → 400 “existiert schon”, the name stays",
        b3.status_code == 400 and b3.json().get("detail") == a.t("api.user_exists")
        and a.get_user(dora)["username"] == "dora" and a.store.bucket_collisions() == [],
        f"HTTP {b3.status_code} {b3.text[:120]}")

# B4: add an address — from LDAP/SAML …
a, b, _ = _pair()
lars = a.create_user("lars", password=PW)
_between(a, "set_email", lambda: b.create_user("lars2", password=PW, email="lars@example.com"))
a._address_proven_by_source(a.store.get_user(lars), "lars@example.com", True, "ldap")
r.check("B4: address from LDAP in a race → the account stays without, audit row",
        not a.get_user(lars)["email"] and "race=1" in (_audit(a, "ldap_email_taken") or ""),
        f"{a.get_user(lars)['email']} {_audit(a, 'ldap_email_taken')}")

# … and from OIDC (if the provider supplies the proof afterwards, the address enters the account — H-3).
IDP = "https://idp.example.invalid"


class _Claims(dict):
    def validate(self, *args, **kw):
        pass


def _set(auth, claims):
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})


def _oidc_login(app):
    cl = TestClient(app, raise_server_exceptions=False)
    start = cl.get("/auth/oidc/start", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return cl.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)


a, b, app_a = _pair(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="secret")
a.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
from tinysesam.oidc import OIDCClient  # noqa: E402
a.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
_set(a, {"sub": "g12c-1", "preferred_username": "olga", "email": "olga@example.com"})
_oidc_login(app_a)
_set(a, {"sub": "g12c-1", "preferred_username": "olga", "email": "olga@example.com", "email_verified": True})
_between(a, "set_email", lambda: b.create_user("olga@example.com", password=PW))
b4 = _oidc_login(app_a)
_olga = a.store.get_user_by_name("olga")
r.check("B4: address from OIDC in a race → no 500, the account stays without, audit row",
        b4.status_code == 303 and _olga is not None and not _olga["email"]
        and "race=1" in (_audit(a, "oidc_email_taken") or ""),
        f"HTTP {b4.status_code} {dict(_olga) if _olga else None} {_audit(a, 'oidc_email_taken')}")

# B5: the routes — registration and admin API answer in substance, never with a 500.
def _register(app, **data):
    return TestClient(app, raise_server_exceptions=False).post(
        "/auth/register", data={"password": PW, "next": "/", **data}, follow_redirects=False)


a, b, app_a = _pair(allow_signup=True)
_between(a, "create_user", lambda: b.create_user("Race", password=PW))
b5a = _register(app_a, username="race", email="r1@example.com")
_between(a, "create_user", lambda: b.create_user("second", password=PW, email="r2@example.com"))
b5b = _register(app_a, username="race2", email="r2@example.com")
r.check("B5: registration in a race without confirmation → 409 (name taken / address taken)",
        b5a.status_code == 409 and html.escape(a.t("err.username_taken")) in b5a.text
        and b5b.status_code == 409 and html.escape(a.t("err.email_taken")) in b5b.text
        and a.store.get_user_by_name("race2") is None,
        f"HTTP {b5a.status_code} / {b5b.status_code}")

a, b, app_a = _pair(allow_signup=True, signup_verify_email=True)
a.set_mailer(lambda *x, **k: True)
_between(a, "create_user", lambda: b.create_user("third", password=PW, email="r3@example.com"))
b5c = _register(app_a, username="race3", email="r3@example.com")
r.check("B5: … with confirmation: an address taken in a race gets the neutral page (R4-03), "
        "Audit signup_taken race=1",
        b5c.status_code == 200 and html.escape(a.t("reg.verify")) in b5c.text
        and a.store.get_user_by_name("race3") is None
        and "race=1" in (_audit(a, "signup_taken") or ""),
        f"HTTP {b5c.status_code} {_audit(a, 'signup_taken')}")
a.create_user("holder", password=PW, email="occupied@example.com")
_between(a, "create_user", lambda: b.create_user("space", password=PW))
b5d = _register(app_a, username="space", email="occupied@example.com")
r.check("B5: … the placeholder for a taken address whose name is taken in a race → 409",
        b5d.status_code == 409 and html.escape(a.t("err.username_taken")) in b5d.text, f"HTTP {b5d.status_code}")

a, b, app_a = _pair(allow_signup=True, signup_verify_email=True, login_identifier="email",
                    signup_require_email=True)
a.set_mailer(lambda *x, **k: True)
_between(a, "create_user", lambda: b.create_user("r4@example.com", password=PW, email="r4@example.com"))
b5e = _register(app_a, email="r4@example.com")
r.check("B5: … in mail mode (name = address): the neutral page, no “name taken” that would reveal the address",
        b5e.status_code == 200 and html.escape(a.t("reg.verify")) in b5e.text, f"HTTP {b5e.status_code}")

a, b, app_a = _pair()
manager = a.create_user("boss", password=PW, is_admin=True)
adm = TestClient(app_a, raise_server_exceptions=False)
adm.cookies.set(a.cfg.session_cookie, a.store.create_session(manager, 3600, True, "password"))
_between(a, "create_user", lambda: b.create_user("svc-race", password=PW))
b5f = adm.post("/auth/admin/api/users", json={"username": "svc-race", "is_service": True})
_between(a, "create_user", lambda: b.create_user("x5", password=PW, email="adm@example.com"))
b5g = adm.post("/auth/admin/api/users", json={"username": "new-adm", "email": "adm@example.com"})
r.check("B5: admin API in a race → 409 “existiert schon” or “E-Mail vergeben”",
        b5f.status_code == 409 and b5f.json().get("detail") == a.t("api.user_exists")
        and b5g.status_code == 409 and b5g.json().get("detail") == a.t("api.email_taken"),
        f"HTTP {b5f.status_code} {b5f.text[:80]} / {b5g.status_code} {b5g.text[:80]}")

# ── C: truly parallel─────────────────────────────────────────────────────────────────────────────
# Two workers, 20 threads each, all on the same identifier — half as name, the other as address.
a, b, app_a = _pair(allow_signup=True)
app_b = FastAPI()
app_b.include_router(b.router())
for _x in (a, b):
    _x.set_security("rate_limit_max", 1000)
IDENTIFIER = "bet@example.com"
N = 40
barrier = threading.Barrier(N)
responses: list = []


def _execution(i):
    data = ({"username": IDENTIFIER, "email": f"t{i}@example.org"} if i % 2 == 0
             else {"username": f"t{i}", "email": IDENTIFIER})
    cl = TestClient((app_a, app_b)[i // 2 % 2], raise_server_exceptions=False)
    try:
        barrier.wait(timeout=30)
        responses.append(cl.post("/auth/register", data={"password": PW, "next": "/", **data},
                                 follow_redirects=False).status_code)
    except Exception as error:        # a thread that fails must not silently be missing
        responses.append(repr(error))


_threads = [threading.Thread(target=_execution, args=(i,)) for i in range(N)]
for _t in _threads:
    _t.start()
for _t in _threads:
    _t.join(timeout=120)
_halter = a.store._all("SELECT id FROM users WHERE folded_name=? OR folded_mail=?", (IDENTIFIER, IDENTIFIER))
r.check("C: 40 simultaneous registrations of the same identifier (name and address, two workers): "
        "only 303/409, exactly one account holds it, no collision",
        len(responses) == N and set(responses) <= {303, 409} and responses.count(303) == 1
        and len(_halter) == 1 and a.store.bucket_collisions() == [],
        f"{sorted(map(str, responses))} Halter {len(_halter)} {a.store.bucket_collisions()}")

# ── D: existing data with collisions ──────────────────────────────────────────────────────────
# (Mutation probes: remove `NEW IS NOT OLD` → red on renaming, the own address and the
#  raw UPDATE; the UPDATE trigger on `OF folded_name, folded_mail` → red, the start fails on the
#  addition; the start message back to “name = foreign address” via NOCASE → red.)
_db_d = _file()
_st = Store(_db_d)
oe1, oe2 = _raw(_st, "Özlem"), _raw(_st, "özlem")
boss, eve = _raw(_st, "chef", "chef@example.com"), _raw(_st, "chef@example.com")
ubu, uxn = _raw(_st, "ubu", "u@bücher.example"), _raw(_st, "uxn", "u@xn--bcher-kva.example")
_st.db.close()


def _start(path):
    return _record("tinysesam", lambda: TinySesam(TinySesamConfig(db_path=path, cookie_secure=False)))


try:
    auth_d, text_d = _start(_db_d)
    start_d = "ok"
except Exception as error:
    auth_d, text_d, start_d = None, "", f"{type(error).__name__}: {error}"
r.check("D: existing data with collisions starts, no bucket stays empty",
        start_d == "ok" and auth_d.store._one("SELECT COUNT(*) AS n FROM users WHERE folded_name IS NULL "
                                              "OR folded_mail IS NULL")["n"] == 0, start_d)
_line = next((z for z in text_d.splitlines() if "identifier collision(s)" in z), "")
r.check("D: … the start message names all three (namesakes, name = foreign address, two spellings "
        "of one address) with their accounts",
        _line.startswith("3 identifier collision(s)")
        and all(f"user_id={i}" in _line for i in (oe1, oe2, boss, eve, ubu, uxn)), _line[:400])
if auth_d is not None:
    in_collision = {
        "new account „ÖZLEM“": _rejected(lambda: auth_d.store.create_user("ÖZLEM")),
        "name → occupied bucket": _rejected(lambda: auth_d.store.set_username(boss, "özlem")),
    }
    r.check("D: … nobody makes a collision worse any more", set(in_collision.values()) == {GRANT},
            str(in_collision))
    resolve = {
        "own address again": _rejected(lambda: auth_d.store.set_email(boss, "chef@example.com", verified=True)),
        "rename account with occupied address": _rejected(lambda: auth_d.store.set_username(ubu, "ubu-new")),
        "change_username to a free name": _rejected(lambda: auth_d.change_username(oe2, "oezlem-two")),
        "set_email to a free address": _rejected(lambda: auth_d.store.set_email(uxn, "u2@example.com")),
        "raw UPDATE des Operators": _rejected(
            lambda: auth_d.store._exec("UPDATE users SET username='eve-renamed' WHERE id=?", (eve,))),
    }
    r.check("D: … resolving works: rename, set the own address anew, a free address, the raw UPDATE",
            set(resolve.values()) == {"by"}, str(resolve))
    _, text_d2 = _start(_db_d)
    r.check("D: … afterwards the start message is silent", "identifier collision(s)" not in text_d2
            and auth_d.store.bucket_collisions() == [], text_d2[:300])
    # A row of a foreign writer counts as soon as someone looks — not only at start.
    # (Mutation probe: remove the addition in `bucket_collisions` → red.)
    _late = _raw(auth_d.store, "ANNA-Maria")
    _raw(auth_d.store, "anna-maria")
    r.check("D: … a collision that a foreign writer creates at runtime is named by bucket_collisions immediately",
            [z["identifier"] for z in auth_d.store.bucket_collisions()] == ["anna-maria"], str(_late))

# ── E: the address change in mail mode is one transaction ─────────────────────────────────────
# A TEMP trigger makes the rename fail. Written separately, the new address then stood
# next to the old name — and the old name kept the old address occupied.
# (Mutation probe: commit after every statement in `_rewrite` → red.)
a, _, app_a = _pair(login_identifier="email", signup_require_email=True)
post = []
a.set_mailer(lambda to, subject, text, html=None: post.append((to, text)))
ella = a.create_user("ella@example.com", password=PW, email="ella@example.com")
a.request_email_change(ella, "ella2@example.com", BASE)()
a.store.db.execute("CREATE TEMP TRIGGER t_probe_broken BEFORE UPDATE OF username ON users "
                   "BEGIN SELECT RAISE(ABORT, 'probe: name fails'); END")
e1 = TestClient(app_a, raise_server_exceptions=False).post(_link(post, "ella2@example.com"), follow_redirects=False)
_ella = a.get_user(ella)
r.check("E: if the rename fails in mail mode, the address stays too — no 500, nothing half-done",
        e1.status_code == 409 and _ella["email"] == "ella@example.com" and _ella["username"] == "ella@example.com"
        and not a.store.db.in_transaction, f"HTTP {e1.status_code} {dict(_ella)}")
a.store.db.execute("DROP TRIGGER temp.t_probe_broken")
post.clear()
a.request_email_change(ella, "ella3@example.com", BASE)()
e2 = TestClient(app_a).post(_link(post, "ella3@example.com"), follow_redirects=False)
_ella = a.get_user(ella)
r.check("E: … without disturbance address and name change together",
        e2.status_code == 303 and _ella["email"] == _ella["username"] == "ella3@example.com", str(dict(_ella)))

# ── F: a file on which the triggers cannot be created ─────────────────────────────────────────
# (Mutation probe: remove the `try` around the creation → red, the start fails.)
_apply = Store._set_trigger


def _not_writable(self):
    raise sqlite3.OperationalError("attempt to write a readonly database")


Store._set_trigger = _not_writable
try:
    _f, text_f = _record("tinysesam", lambda: Store(_file()))
    start_f = "ok"
except Exception as error:
    text_f, start_f = "", f"{type(error).__name__}: {error}"
finally:
    Store._set_trigger = _apply
r.check("F: if the triggers cannot be created (read-only), the store starts anyway and says so",
        start_f == "ok" and "only enforces the shared identifier space after a start with write access" in text_f,
        f"{start_f} {text_f[:200]!r}")

# ── G: the check does not cost more with the number of accounts ───────────────────────────────
# SQLite steps are counted (like S-1 in tests/test_audit_round2.py): a scan over the accounts
# costs at least one step per row, an index access one, no matter how deep the tree is.
# (Mutation probe: in the trigger `folded_name || '' = …` instead of `folded_name = …` — no index any more → red.)
def _steps(st, fn) -> int:
    counter = [0]

    def step():
        counter[0] += 1
        return 0
    st.db.set_progress_handler(step, 1)
    try:
        fn()
    finally:
        st.db.set_progress_handler(None, 1)
    return counter[0]


def _measure(n: int) -> dict:
    st = Store(_file())
    st.db.executemany("INSERT INTO users(username, email, created_at) VALUES (?, ?, 1)",
                      [(f"account{i}", f"account{i}@example.com") for i in range(n)])
    st.db.commit()
    st._backfill_pots()
    uid = st.create_user("probe")
    return {"create": _steps(st, lambda: st.create_user("new", email="new@example.org")),
            "umbenennen": _steps(st, lambda: st.set_username(uid, "probe-new")),
            "Address": _steps(st, lambda: st.set_email(uid, "probe@example.org")),
            "rejected": _steps(st, lambda: _rejected(lambda: st.create_user("ACCOUNT7")))}


_small, _gross = _measure(100), _measure(3000)
_grows = {k: (_small[k], _gross[k]) for k in _small if abs(_gross[k] - _small[k]) > 100}
r.check("G: creating, renaming, setting an address and rejecting cost no more with 3000 accounts than with 100",
        not _grows, f"grows: {_grows}\n100: {_small}\n3000: {_gross}")

sys.exit(r.done())
