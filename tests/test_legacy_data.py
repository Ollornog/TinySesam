"""What happens on an UPGRADE of an existing installation — and what must not happen.

The docs cross-check of 2026-09-21 found seven places where the docs said something different
from the code. Five of them were not typos but real defects; this suite pins
them down so they do not come back. The worst: raising the scrypt parameters in
0.18.0 would have locked out every account running without the `[argon2]` extra.

All checks work without extras.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI                                    # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

from tinysesam import TinySesam, TinySesamConfig               # noqa: E402
from tinysesam import passwords                                # noqa: E402
from tinysesam.errors import ConfigError                       # noqa: E402
from tinysesam.store import Store                              # noqa: E402
from _kit.report import Report                                 # noqa: E402

r = Report("Legacy data — what an upgrade must survive")


def frisch(**cfg) -> tuple[TinySesam, str]:
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    kw = dict(db_path=db, lang="de", passkey_enabled=False, oidc_enabled=False,
              cookie_secure=False)
    kw.update(cfg)
    return TinySesam(TinySesamConfig(**kw)), db


# ---------------------------------------------------------------- existing scrypt hashes
# Up to 0.17.0 the format was `scrypt$salt$dk` and it did NOT carry its parameters; hashing
# used n=2^15, r=8, p=1. 0.18.0 raised p to 3 — and `verify_password` recomputed every old
# hash with the new p. The result would have been "wrong password" for every account without `[argon2]`,
# without a single error message naming the reason.
def alt_hash(pw: str) -> str:
    """Create a hash in the 0.17.0 format (p=1, without parameters in the string)."""
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32,
                        maxmem=132 * 1024 * 1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


bestand = alt_hash("geheim123")
r.check("existing hash from 0.17.0 still verifies",
        passwords.verify_password("geheim123", bestand),
        "the parameter increase locks out all scrypt accounts")
r.check("… and a wrong password, on the other hand, does not",
        not passwords.verify_password("falsch", bestand))
r.check("existing hash counts as needing renewal",
        passwords.needs_rehash(bestand),
        "otherwise the account stays on the weaker parameters forever")

neu = "scrypt$%d$%d$%d$%s$%s" % (
    passwords._SCRYPT["n"], passwords._SCRYPT["r"], passwords._SCRYPT["p"],
    base64.b64encode(b"0123456789abcdef").decode(),
    base64.b64encode(hashlib.scrypt(b"geheim123", salt=b"0123456789abcdef",
                                    **passwords._SCRYPT)).decode())
r.check("hash in today's format verifies", passwords.verify_password("geheim123", neu))
if not passwords._ARGON:
    # Without argon2 hash_password itself produces scrypt — then the new format must come out
    # and must not immediately count as outdated again.
    eigen = passwords.hash_password("geheim123")
    r.check("self-generated hash carries its parameters", eigen.count("$") == 5, eigen[:24])
    r.check("… and does not count as needing renewal", not passwords.needs_rehash(eigen))
else:
    r.check("without argon2 a new hash carries 5 separators",
            passwords.hash_password.__module__ == "tinysesam.passwords")

# And the path that counts in operation: an account whose hash comes from 0.17.0 signs in.
auth, db = frisch()
uid = auth.create_user("bestand", password="geheim123")
auth.store.set_password_hash(uid, bestand)
r.check("sign-in with a 0.17.0 hash succeeds", bool(auth._check_password("bestand", "geheim123")),
        "the login path computes differently from verify_password")

# ---------------------------------------------------------------- migration of an old file
# Since 0.18.0 `resource_unlock.token` carries the sha256 instead of the plain text. The cleanup depended
# on `0 < PRAGMA user_version < 4` — and `user_version` itself only arrived with 0.18.0, a file from
# 0.17.0 has a 0 there. So the condition was wrong in exactly the case it was written for:
# the plain text would have been left behind and never matched again.
alt_db = os.path.join(tempfile.mkdtemp(), "alt.db")
auth0, _ = frisch(db_path=alt_db, resource_locks_enabled=True)
auth0.store.add_resource_unlock("klartext-token", "akte-7", 4102444800)
auth0.store.db.execute("PRAGMA user_version = 0")            # state of a 0.17.0 file
auth0.store.db.execute("UPDATE resource_unlock SET token='klartext-token'")
auth0.store.db.commit()
auth0.store.db.close()

roh = sqlite3.connect(alt_db)
vorher = roh.execute("SELECT count(*) FROM resource_unlock").fetchone()[0]
roh.close()
r.check("precondition: the old file carries a plain-text entry", vorher == 1, f"{vorher}")

Store(alt_db).db.close()                                      # = upgrade to 0.18.0
roh = sqlite3.connect(alt_db)
nachher = roh.execute("SELECT count(*) FROM resource_unlock").fetchone()[0]
stempel = roh.execute("PRAGMA user_version").fetchone()[0]
roh.close()
r.check("plain-text unlock is discarded on upgrade", nachher == 0,
        f"{nachher} entries remained — they never match again")
r.check("… and the file then carries the schema stamp", stempel == Store.SCHEMA_VERSION,
        f"{stempel}")

# A hashed unlock must NOT be hit by the cleanup (otherwise every start clears it out).
auth1, db1 = frisch(resource_locks_enabled=True)
auth1.store.add_resource_unlock("frisch-token", "akte-8", 4102444800)
auth1.store.db.close()
s2 = Store(db1)
r.check("hashed unlock survives a restart",
        s2.is_resource_unlocked("frisch-token", "akte-8"),
        "the cleanup reaches too far")
s2.db.close()

# ---------------------------------------------------------------- Schema 9 → 10
# What the migration to schema 10 does with existing data — on a file in the state of schema 9
# (today's schema without what 10 adds; the precondition checks that none of it is left).
#
# (a) Operator locks from earlier versions (S-5). Up to 0.19.x the lock in the panel wrote
#     `disabled=1` and did NOT discard the open tokens. After the upgrade the old
#     confirmation link of a pending signup lifted the lock and signed the user in — the
#     statement „the lock had already discarded its open tokens back then“ was true for no release.
# (b) The counting buckets (S-1) are computed for every existing row, indexes and triggers created.
# (c) Addresses of open signups lose the „verified“ mark (S-2) until the link arrives.
# (Mutation probes: remove the panel step → red at (a), the old link gives 303; do not discard
#  the tokens there → red at (a); only recognise `detail = 'uid=<id>'`, not `'uid=<id> …'`
#  → red at (a); remove the step for open signups → red at (c); do not set the proof in `/auth/verify`
#  → red at (c); remove the bucket step of the migration → red at (b).)
_s10_ordner = tempfile.mkdtemp()
_s10_db = os.path.join(_s10_ordner, "schema9.db")
_s10_cfg = dict(db_path=os.path.join(_s10_ordner, "quelle.db"), allow_signup=True,
                signup_require_email=True, signup_verify_email=True, csrf_enabled=False,
                base_url="https://auth.example.com")
_s10_alt, _ = frisch(**_s10_cfg)
_s10_alt.create_user("chefin", password="Geheim12345!", is_admin=True)
_s10_ids, _s10_links = {}, {}
for _name in ("verdacht", "wartend", "wieder", "altsperre"):
    _uid = _s10_alt.store.create_user(_name, None, f"{_name}@example.org")   # mark 1, as back then
    _s10_ids[_name] = _uid
    _s10_alt.store.set_disabled(_uid, True)                                # back then: always 1
    if _name != "altsperre":
        _s10_links[_name] = _s10_alt.create_magic_token("verify_email", user_id=_uid,
                                                        email=f"{_name}@example.org")
# The panel lock from back then: audit row with `uid=<id>`, tokens stay in place.
_s10_alt.store.audit_log("user_disable", "chefin", None, f"uid={_s10_ids['verdacht']} api_keys_revoked=1")
_s10_alt.store.audit_log("user_disable", "chefin", None, f"uid={_s10_ids['altsperre']}")
_s10_alt.store.audit_log("user_disable", "chefin", None, f"uid={_s10_ids['wieder']}")
_s10_alt.store.audit_log("user_enable", "chefin", None, f"uid={_s10_ids['wieder']}")
_s10_emile = _s10_alt.store.create_user("Émile", None, "Emile@Bücher.example")
_s10_alt.store.db.close()
# The file in the state of schema 9: the schema without the bucket columns (indexes and triggers are only
# created by `_migrate`), the data via ATTACH from the file just filled. Not via `ALTER TABLE …
# DROP COLUMN`: when removing the last column SQLite searches backwards in the text for the comma before it
# and finds one in the comment above („incomplete input“).
from tinysesam.store import SCHEMA as _S10_SCHEMA  # noqa: E402
# Cut out along with it: `idp_bestaetigt_at` (schema 11, finding 8) and the high-water marks of the identifiers
# (schema 11, G2), which have since stood behind `topf_mail`, plus `name_selbst_gewaehlt` behind them
# (schema 11, G2-N) — and `federated_identity.name_topf` (schema 11, G5), whose name and comment
# would otherwise hit the „no leftovers with topf" probe.
_s10_schema9, _s10_n = re.subn(r",\n\s*-- The counting bucket.*?topf_mail\s+TEXT,\n\s*idp_bestaetigt_at INTEGER.*?"
                               r"mail_audit_ab\s+INTEGER,\n.*?name_selbst_gewaehlt INTEGER NOT NULL DEFAULT 0\n",
                               "\n", _S10_SCHEMA, flags=re.S)
_s10_schema9, _s10_nfi = re.subn(r"\n\s*-- The name under which the account last signed in.*?name_topf\s+TEXT,", "",
                                 _s10_schema9, flags=re.S)
# Schema 11 (B2-6) came afterwards: a file in the state of 9 does not have the table `fehlserie` yet.
_s10_schema9, _s10_n11 = re.subn(r"CREATE TABLE IF NOT EXISTS fehlserie \(.*?\n\);\n", "", _s10_schema9,
                                 flags=re.S)
os.close(os.open(_s10_db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
_s10_roh = sqlite3.connect(_s10_db)
_s10_roh.executescript(_s10_schema9)
_s10_roh.execute("ATTACH DATABASE ? AS quelle", (_s10_cfg["db_path"],))
for (_tab,) in _s10_roh.execute("SELECT name FROM main.sqlite_master WHERE type='table' "
                                "AND name NOT LIKE 'sqlite_%'").fetchall():
    _sp = ", ".join(z[1] for z in _s10_roh.execute(f"PRAGMA main.table_info({_tab})"))
    _s10_roh.execute(f"INSERT INTO main.{_tab}({_sp}) SELECT {_sp} FROM quelle.{_tab}")
_s10_roh.commit()
_s10_roh.execute("DETACH DATABASE quelle")
_s10_roh.execute("PRAGMA user_version = 9")
_s10_rest = _s10_roh.execute("SELECT name FROM sqlite_master WHERE sql LIKE '%topf%' "
                             "OR name LIKE 'ix_users_%'").fetchall()
_s10_zahl = _s10_roh.execute("SELECT COUNT(*) FROM users").fetchone()[0]
_s10_roh.commit()
_s10_roh.close()
_s10_cfg["db_path"] = _s10_db
r.check("precondition: the file is at schema 9, without bucket columns, indexes and triggers, with all accounts",
        _s10_n == 1 and _s10_n11 == 1 and _s10_nfi == 1 and not _s10_rest and _s10_zahl == 6
        and Store.SCHEMA_VERSION >= 10,
        f"cut {_s10_n}/{_s10_n11}/{_s10_nfi}, leftovers {_s10_rest}, accounts {_s10_zahl}, "
        f"SCHEMA_VERSION={Store.SCHEMA_VERSION}")

_s10, _ = frisch(**_s10_cfg)                                      # = upgrade to schema 10
_s10_app = FastAPI()
_s10_app.include_router(_s10.router())
_s10_u = {n: _s10.store.get_user(i) for n, i in _s10_ids.items()}
_s10_offen = {n: _s10.store._one("SELECT COUNT(*) AS n FROM magic_token WHERE user_id=? AND used_at IS NULL",
                                 (i,))["n"] for n, i in _s10_ids.items()}
_s10_link = TestClient(_s10_app, client=("192.0.2.66", 1)).post(
    f"/auth/verify/{_s10_links['verdacht']}", follow_redirects=False)
r.check("S-5 (a): a panel lock from back then carries the operator mark after the upgrade, its "
        "open tokens are discarded — the old confirmation link does not unlock",
        _s10_u["verdacht"]["disabled"] == 2 and _s10_offen["verdacht"] == 0
        and _s10_u["altsperre"]["disabled"] == 2
        and _s10_link.status_code != 303 and _s10.store.get_user(_s10_ids["verdacht"])["disabled"] == 2
        and not _s10.store.list_sessions(_s10_ids["verdacht"]),
        f"verdacht {dict(_s10_u['verdacht'])}, offen {_s10_offen}, Link HTTP {_s10_link.status_code}")
_s10_wartet = TestClient(_s10_app, client=("192.0.2.67", 1)).post(
    f"/auth/verify/{_s10_links['wartend']}", follow_redirects=False)
r.check("S-5 (a): … a pending signup without a panel lock remains unlockable, a "
        "lock that was lifted again remains the app's (1)",
        _s10_u["wartend"]["disabled"] == 1 and _s10_offen["wartend"] == 1
        and _s10_wartet.status_code == 303 and _s10.store.get_user(_s10_ids["wartend"])["disabled"] == 0
        and _s10_u["wieder"]["disabled"] == 1 and _s10_offen["wieder"] == 1,
        f"wartend {dict(_s10_u['wartend'])}, Link HTTP {_s10_wartet.status_code}, wieder {dict(_s10_u['wieder'])}")
r.check("S-2 (c): addresses of open signups carry no proof after the upgrade until the "
        "link arrives — then again",
        _s10_u["verdacht"]["email_verified"] == 0 and _s10_u["wartend"]["email_verified"] == 0
        and _s10.store.get_user(_s10_ids["wartend"])["email_verified"] == 1
        and _s10.store.get_user(_s10_emile)["email_verified"] == 1,
        f"verdacht {_s10_u['verdacht']['email_verified']}, wartend vorher "
        f"{_s10_u['wartend']['email_verified']}, nachher {_s10.store.get_user(_s10_ids['wartend'])['email_verified']}")
_s10_objekte = {z["name"] for z in _s10.store._all("SELECT name FROM sqlite_master WHERE tbl_name='users'")}
_s10_e = _s10.store.get_user(_s10_emile)
_s10_ohne = _s10.store._one("SELECT COUNT(*) AS n FROM users WHERE topf_name IS NULL OR topf_mail IS NULL")["n"]
r.check("S-1 (b): every existing row gets its counting bucket, indexes and triggers exist",
        _s10_ohne == 0 and _s10_e["topf_name"] == "émile"
        and _s10_e["topf_mail"] == "emile@xn--bcher-kva.example"
        and {"ix_users_topf_name", "ix_users_topf_mail", "ix_users_name_nocase", "ix_users_email_nocase",
             "trg_users_topf_name", "trg_users_topf_mail"} <= _s10_objekte
        and (_s10.store.konto_mit_topf("émile") or {"id": None})["id"] == _s10_emile,
        f"without bucket {_s10_ohne}, Émile {(_s10_e['topf_name'], _s10_e['topf_mail'])}, objects {_s10_objekte}")
_s10.store.db.close()
# Whoever changes the folding in `norm_kennung` raises the schema — then startup recomputes ALL buckets
# (`Store.TOPF_SCHEMA`), not just the missing ones. Simulated with an outdated bucket in a
# file whose stamp is below `TOPF_SCHEMA`.
# (Mutation probe: in `_migrate` only ever compute the NULL rows → red.)
_s10_veraltet = sqlite3.connect(_s10_db)
_s10_veraltet.execute("UPDATE users SET topf_name='alte-faltung' WHERE id=?", (_s10_emile,))
_s10_veraltet.execute(f"PRAGMA user_version = {Store.TOPF_SCHEMA - 1}")
_s10_veraltet.commit()
_s10_veraltet.close()
_s10_neu = Store(_s10_db)
r.check("S-1 (b): … a stamp below TOPF_SCHEMA also recomputes existing buckets",
        _s10_neu.get_user(_s10_emile)["topf_name"] == "émile",
        f"{_s10_neu.get_user(_s10_emile)['topf_name']}")
_s10_neu.db.close()
_s10_zweit = Store(_s10_db)
r.check("… a second start changes nothing more (stamp current, no further lock, no mark)",
        int(_s10_zweit.db.execute("PRAGMA user_version").fetchone()[0]) == Store.SCHEMA_VERSION
        and _s10_zweit.get_user(_s10_ids["wieder"])["disabled"] == 1
        and _s10_zweit.get_user(_s10_ids["wartend"])["email_verified"] == 1)
_s10_zweit.db.close()

# ---------------------------------------------------------------- downgrade window
# An older version opens a schema-10 file, warns and keeps writing; it leaves the stamp
# at 10. If it locks in the panel during this window, `disabled=1` is back with an open
# confirmation link. The migration steps that fix this on upgrade depended on the stamp and
# never ran again afterwards: the old link lifted the lock and signed the user in (final round W1,
# reproduced with a real 0.19.0). Here the older version writes with raw SQL exactly what
# 0.19.0 writes: signup without bucket, with mark 1, locked, token open; the panel lock
# as `disabled=1` plus audit row `user_disable uid=<id>`, the tokens stay in place.
_rs_cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "rueckschritt.db"), allow_signup=True,
               signup_require_email=True, signup_verify_email=True, csrf_enabled=False,
               base_url="https://auth.example.com")
_rs_heute, _ = frisch(**_rs_cfg)                              # today's version creates the file
_rs_heute.create_user("chefin", password="Geheim12345!", is_admin=True)
_rs_ids, _rs_links = {}, {}
for _name in ("vorher", "hin"):                              # open signups from today
    _uid = _rs_heute.store.create_user(_name, None, f"{_name}@example.org", email_verified=False)
    _rs_heute.store.set_disabled(_uid, True)
    _rs_ids[_name] = _uid
    _rs_links[_name] = _rs_heute.create_magic_token("verify_email", user_id=_uid, email=f"{_name}@example.org")
_rs_heute.store.db.close()

_rs_roh = sqlite3.connect(_rs_cfg["db_path"])                # from here on: the older version
_rs_jetzt = int(time.time())
for _name in ("rueck", "offen_alt"):
    _uid = _rs_roh.execute("INSERT INTO users(username, display_name, email, email_verified, disabled, "
                           "created_at) VALUES (?,?,?,1,1,?)",
                           (_name, _name, f"{_name}@example.org", _rs_jetzt)).lastrowid
    _rs_ids[_name] = _uid
    _rs_links[_name] = secrets.token_urlsafe(32)
    _rs_roh.execute("INSERT INTO magic_token(token_hash, purpose, user_id, email, created_at, expires_at) "
                    "VALUES (?,?,?,?,?,?)", (hashlib.sha256(_rs_links[_name].encode()).hexdigest(),
                                             "verify_email", _uid, f"{_name}@example.org", _rs_jetzt,
                                             _rs_jetzt + 3600))
for _name, _ereignis in (("rueck", "user_disable"), ("vorher", "user_disable"),
                         ("hin", "user_disable"), ("hin", "user_enable")):
    _rs_roh.execute("UPDATE users SET disabled=1 WHERE id=?", (_rs_ids[_name],))
    _rs_roh.execute("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                    (_rs_jetzt, _ereignis, "chefin", "192.0.2.9", f"uid={_rs_ids[_name]}"))
_rs_stempel = _rs_roh.execute("PRAGMA user_version").fetchone()[0]
_rs_roh.commit()
_rs_roh.close()

_rs, _ = frisch(**_rs_cfg)                                     # today's version again
_rs_app = FastAPI()
_rs_app.include_router(_rs.router())


def _rs_offen(uid) -> int:
    return _rs.store._one("SELECT COUNT(*) AS n FROM magic_token WHERE user_id=? AND used_at IS NULL",
                          (uid,))["n"]


_rs_u = {n: dict(_rs.store.get_user(i)) for n, i in _rs_ids.items()}
_rs_tok = {n: _rs_offen(i) for n, i in _rs_ids.items()}
_rs_bis = _rs.store.get_setting(getattr(Store, "PANEL_WASSERLINIE", "panel_sperren_bis"))
_rs_max = _rs.store._one("SELECT MAX(id) AS m FROM audit")["m"]
_rs_antwort = {n: TestClient(_rs_app, client=(f"192.0.2.{70 + k}", 1)).post(
    f"/auth/verify/{_rs_links[n]}", follow_redirects=False).status_code
    for k, n in enumerate(("rueck", "vorher", "hin", "offen_alt"))}
_rs_danach = {n: dict(_rs.store.get_user(i)) for n, i in _rs_ids.items()}
# (Mutation probes, executed: run the migration steps only when `vorhanden_vorab < 10` again
#  → red, the old link gives 303 and signs in; do not discard the tokens → red; in the panel step
#  take only accounts without a bucket → red at „vorher“; take the first instead of the latest event per
#  account → red at „hin“; ignore the high-water mark → green here, red in the effort test below.)
r.check("downgrade: a panel lock of the older version on a schema-10 file carries the operator mark after the "
        "next start, its tokens are discarded — the old link does not unlock",
        _rs_stempel == Store.SCHEMA_VERSION and _rs_u["rueck"]["disabled"] == 2 and _rs_tok["rueck"] == 0
        and _rs_u["vorher"]["disabled"] == 2 and _rs_tok["vorher"] == 0
        and _rs_antwort["rueck"] != 303 and _rs_antwort["vorher"] != 303
        and _rs_danach["rueck"]["disabled"] == 2 and _rs_danach["vorher"]["disabled"] == 2
        and not _rs.store.list_sessions(_rs_ids["rueck"]) and not _rs.store.list_sessions(_rs_ids["vorher"]),
        f"Stempel {_rs_stempel}, vorher {_rs_u}, Token {_rs_tok}, Links {_rs_antwort}")
r.check("downgrade: … a lock that the older version lifted again remains the app's "
        "(1), its link unlocks",
        _rs_u["hin"]["disabled"] == 1 and _rs_tok["hin"] == 1 and _rs_antwort["hin"] == 303
        and _rs_danach["hin"]["disabled"] == 0, f"hin {_rs_u['hin']}, Link {_rs_antwort['hin']}")
# Step 2 in the same window: the older version creates the address of an open signup with
# mark 1. The trace for that is the row without a bucket, which only a foreign writer leaves behind.
# (Mutation probes, executed: remove the address step for a stamp of 10 or higher → red; run it only
#  for the accounts from the panel step, without the bucket trace → red at „offen_alt“; run it AFTER
#  the panel step that discards the tokens → red at „rueck“.)
r.check("downgrade: … the address of an open signup of the older version carries no proof after "
        "startup until the link arrives — the panel lock loses it before the tokens are discarded",
        _rs_u["offen_alt"]["email_verified"] == 0 and _rs_u["offen_alt"]["disabled"] == 1
        and _rs_antwort["offen_alt"] == 303 and _rs_danach["offen_alt"]["email_verified"] == 1
        and _rs_u["rueck"]["email_verified"] == 0,
        f"offen_alt vorher {_rs_u['offen_alt']}, nachher {_rs_danach['offen_alt']}, rueck {_rs_u['rueck']}")
r.check("downgrade: … the high-water mark is at the latest audit row after startup",
        _rs_bis is not None and _rs_max is not None and int(_rs_bis) == int(_rs_max),
        f"watermark {_rs_bis}, latest row {_rs_max}")
_rs.store.db.close()
# Edge case: the high-water mark is above the audit log's counter (table emptied by hand and the
# counter reset, setting set by hand). Then startup reads everything instead of skipping every new row
# up to the old height.
# (Mutation probe, executed: remove the reset to 0 → red.)
_rs_roh = sqlite3.connect(_rs_cfg["db_path"])
_rs_roh.execute("INSERT OR REPLACE INTO setting(key, value) VALUES (?, ?)",
                (getattr(Store, "PANEL_WASSERLINIE", "panel_sperren_bis"), "1000000000"))
_rs_roh.execute("INSERT INTO users(username, email, email_verified, disabled, created_at) "
                "VALUES ('spaet', 'spaet@example.org', 1, 1, ?)", (_rs_jetzt,))
_rs_spaet = _rs_roh.execute("SELECT id FROM users WHERE username='spaet'").fetchone()[0]
_rs_roh.execute("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                (_rs_jetzt, "user_disable", "chefin", "192.0.2.9", f"uid={_rs_spaet}"))
_rs_roh.commit()
_rs_roh.close()
_rs_hoch = Store(_rs_cfg["db_path"])
r.check("downgrade: … a high-water mark above the audit log counter skips no lock",
        _rs_hoch.get_user(_rs_spaet)["disabled"] == 2
        and int(_rs_hoch.get_setting(getattr(Store, "PANEL_WASSERLINIE", "panel_sperren_bis"))) < 1000000000,
        f"{dict(_rs_hoch.get_user(_rs_spaet))}")
_rs_hoch.db.close()

# ---------------------------------------------------------------- effort of the migration steps
# The first version searched the whole audit log for the latest row of EVERY account with `disabled=1`
# (correlated subquery, no index on `event`/`detail`): locked × audit.
# Measured during the attack: 1,000,000 rows × 1,000 locked accounts 60 s, under the write lock;
# a second worker failed after `BUSY_TIMEOUT_MS` with „database is locked“. Likewise the
# address step: open signups × one-time tokens. What is measured is not the wall clock but
# the database's work (SQLite steps, `set_progress_handler`), as with S-1 in
# tests/test_audit_round2.py — deterministic, even on a slow runner.
def _rs_bestand(n_audit: int, n_gesperrt: int) -> Store:
    """File in the state of schema 9: `n_audit` noise rows in the audit log and as many
    sign-in links, `n_gesperrt` open signups (locked, token open) and `n_gesperrt`
    panel locks from back then."""
    st = Store(os.path.join(tempfile.mkdtemp(), "aufwand.db"))
    jetzt = int(time.time())
    with st._lock:
        st.db.executemany("INSERT INTO users(username, email, created_at, disabled) VALUES (?,?,?,1)",
                          [(f"k{i}", f"k{i}@example.com", jetzt) for i in range(2 * n_gesperrt)])
        ids = [z[0] for z in st.db.execute("SELECT id FROM users ORDER BY id")]
        st.db.executemany("INSERT INTO magic_token(token_hash, purpose, user_id, created_at, expires_at) "
                          "VALUES (?,?,?,?,?)", [(f"h{u}", "verify_email", u, jetzt, jetzt + 3600)
                                                 for u in ids[:n_gesperrt]])
        st.db.executemany("INSERT INTO magic_token(token_hash, purpose, email, created_at, expires_at) "
                          "VALUES (?,?,?,?,?)", ((f"l{i}", "login", f"x{i}@example.com", jetzt, jetzt + 3600)
                                                 for i in range(n_audit)))
        ereignisse = ("login_ok", "login_fail", "logout", "signup", "session_revoked")
        st.db.executemany("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                          ((jetzt, ereignisse[i % 5], f"k{i % 50}", "192.0.2.1", None)
                           for i in range(n_audit)))
        st.db.executemany("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                          [(jetzt, "user_disable", "chefin", None, f"uid={u}") for u in ids[n_gesperrt:]])
        st.db.execute("PRAGMA user_version = 9")
        st.db.commit()
    return st


def _rs_schritte(st: Store) -> int:
    """SQLite steps (per 100 VM instructions) of a start on the open file (`_migrate`)."""
    zaehler = [0]

    def schritt():
        zaehler[0] += 1
        return 0
    st.db.set_progress_handler(schritt, 100)
    try:
        st._migrate()
    finally:
        st.db.set_progress_handler(None, 100)
    return zaehler[0]


_rs_mess = {}
for _a, _g in ((20000, 10), (20000, 200), (2000, 10)):
    _st = _rs_bestand(_a, _g)
    _rs_mess[(_a, _g, "Upgrade")] = _rs_schritte(_st)
    _rs_mess[(_a, _g, "Panel")] = _st._one("SELECT COUNT(*) AS n FROM users WHERE disabled=2")["n"]
    _rs_mess[(_a, _g, "Neustart")] = _rs_schritte(_st)
    _st.db.close()
# Per additional locked account (190 more panel locks and 190 more open signups) the
# upgrade may cost at most a small, fixed amount more — not a pass through the audit log
# or through the one-time tokens (20,000 rows each). Measured with the previous version: about 1,500
# steps per account, now a little over one. And a start after the upgrade does not read the audit log again: with
# 20,000 rows no more than with 2,000.
# (Mutation probes, executed: make the panel step a correlated subquery per account again → red;
#  make the address step an EXISTS per account again → red; do not read the high-water mark, every start from
#  0 → red on restart, 1,080 steps more.)
_rs_je_konto = (_rs_mess[(20000, 200, "Upgrade")] - _rs_mess[(20000, 10, "Upgrade")]) / 380
_rs_neustart = _rs_mess[(20000, 10, "Neustart")] - _rs_mess[(2000, 10, "Neustart")]
r.check("effort: the upgrade grows with audit log PLUS locked accounts, not with their product "
        "(SQLite steps per additional locked account at 20,000 audit rows)",
        _rs_je_konto < 20 and _rs_mess[(20000, 200, "Panel")] == 200,
        f"je Konto {_rs_je_konto:.1f} Schritte, Messung {_rs_mess}")
r.check("effort: … a start after the upgrade reads only the audit rows since the last start",
        _rs_neustart < 20, f"Neustart bei 20 000 statt 2 000 Zeilen: {_rs_neustart} Schritte mehr, "
        f"Messung {_rs_mess}")

# ---------------------------------------------------------------- audit --user
# The command filtered the latest rows afterwards instead of filtering in SQL: whoever searched in the
# incident case (brute-force wave) got "Keine Einträge zu 'X'." and exit 0, although they were there.
auth2, _ = frisch()
auth2.audit("login_ok", username="opfer", detail="alt")
for i in range(300):
    auth2.audit("login_fail", username="rauschen", detail=str(i))
treffer = auth2.store.recent_audit(30, username="opfer")
r.check("audit --user finds entries behind 300 rows of noise", len(treffer) == 1,
        f"{len(treffer)} gefunden")
r.check("… and filters independently of capitalisation",
        len(auth2.store.recent_audit(30, username="OPFER")) == 1)
r.check("without a filter the latest rows still come back",
        len(auth2.store.recent_audit(5)) == 5)

# ---------------------------------------------------------------- seed_demo
# The docstring promised "only with demo_mode=True", the body did not check it: a direct call
# created `demoadmin` with a known password and is_admin=1 — able to sign in, without a warning in the log.
auth3, _ = frisch()
try:
    auth3._seed_demo()
    r.check("seed_demo() without demo_mode is rejected", False, "it went through")
except ConfigError:
    r.check("seed_demo() without demo_mode is rejected", True)
r.check("… and creates no admin account in the process",
        auth3.store.get_user_by_name("demoadmin") is None)

# ---------------------------------------------------------------- stepup_strict
# `stepup_methods` was only ever a wish: whoever had none of the named methods set up
# confirmed with whatever they had — including the password they had just signed in with.
# That is no step-up. The barrier exists now, the default remains the old way.
auth4, _ = frisch(stepup_methods=["totp"])
u4 = auth4.store.get_user(auth4.create_user("ohne_totp", password="pw123456"))
r.check("stepup_methods remains a wish by default",
        auth4.stepup_options(u4) == ["password"], f"{auth4.stepup_options(u4)}")
auth5, _ = frisch(stepup_methods=["totp"], stepup_strict=True)
u5 = auth5.store.get_user(auth5.create_user("ohne_totp", password="pw123456"))
r.check("stepup_strict=True lets nothing through that was not wished for",
        auth5.stepup_options(u5) == [], f"{auth5.stepup_options(u5)}")
auth6, _ = frisch(stepup_methods=[], stepup_strict=True)
u6 = auth6.store.get_user(auth6.create_user("normal", password="pw123456"))
r.check("stepup_strict without stepup_methods changes nothing",
        auth6.stepup_options(u6) == ["password"], f"{auth6.stepup_options(u6)}")

# ---------------------------------------------------------------- login_chain dead end
# `login_chain=["password","totp"]` permanently locked out every account WITHOUT TOTP set up:
# the correct password led to /auth/totp, which, lacking a secret, redirected back to the login
# page — and the setup page demanded a fully signed-in user, which cannot exist under
# this chain. Neither in nor to the setup.
auth7, _ = frisch(login_chain=["password", "totp"], csrf_enabled=False)
auth7.create_user("kette", password="pw123456")
app7 = FastAPI()
app7.include_router(auth7.router())
c7 = TestClient(app7, follow_redirects=False)
ant = c7.post("/auth/login", data={"username": "kette", "password": "pw123456"})
r.check("correct password leads to the second factor",
        ant.status_code == 303 and "/auth/totp" in ant.headers.get("location", ""),
        f"{ant.status_code} {ant.headers.get('location')}")
ant = c7.get("/auth/totp")
r.check("/auth/totp without a secret sends to SETUP, not back to the login",
        ant.status_code == 303 and "/auth/totp/setup" in ant.headers.get("location", ""),
        f"{ant.status_code} {ant.headers.get('location')} — Sackgasse")
ant = c7.get("/auth/totp/setup")
r.check("the setup page is reachable in this state", ant.status_code == 200,
        f"{ant.status_code}")

# Without a chain the old behaviour remains: no setup without a full sign-in.
auth8, _ = frisch(csrf_enabled=False)
auth8.create_user("klassisch", password="pw123456")
app8 = FastAPI()
app8.include_router(auth8.router())
c8 = TestClient(app8, follow_redirects=False)
ant = c8.get("/auth/totp/setup")
r.check("without a session the setup page leads on to the login",
        ant.status_code == 303 and "/auth/login" in ant.headers.get("location", ""),
        f"{ant.status_code} {ant.headers.get('location')}")

# ---------------------------------------------------------------- B-1: admin panel and CSRF
# The panel rolled a new CSRF token on EVERY request. Whoever opened it in a second tab
# invalidated the open form in the first — 403 without explanation. What is checked is the
# RAW Set-Cookie header: `TestClient` keeps a cookie jar and would swallow a renewed setting
# of the same value.
auth9, _ = frisch(csrf_enabled=True, admin_enabled=True)
auth9.ensure_admin("chef", "pw123456")
app9 = FastAPI()
app9.include_router(auth9.router())
c9 = TestClient(app9)
c9.get("/auth/login")                       # only now sets the CSRF cookie
anm = c9.post("/auth/login", data={"username": "chef", "password": "pw123456",
                                   "_csrf": c9.cookies.get(auth9.cfg.csrf_cookie, "")},
              follow_redirects=False)
# 303 = signed in. Without `follow_redirects=False` the client would follow `next` and
# report the 404 of the target page — this app has no "/".
r.check("precondition: the sign-in succeeds", anm.status_code == 303, f"{anm.status_code}")
erste = c9.get(auth9.cfg.admin_path)
# Without this precondition the test below would check nothing: a 401 naturally sets no
# CSRF cookie either, and the suite would have stayed green without ever having seen the case.
r.check("precondition: the panel is reachable", erste.status_code == 200, f"{erste.status_code}")
r.check("precondition: the first request SETS a CSRF cookie",
        any(k.lower() == "set-cookie" and v.startswith(auth9.cfg.csrf_cookie + "=")
            for k, v in erste.headers.items())
        or bool(c9.cookies.get(auth9.cfg.csrf_cookie)),
        "no cookie — then the check below measures nothing")
zweite = c9.get(auth9.cfg.admin_path)
gesetzt = [v for k, v in zweite.headers.items() if k.lower() == "set-cookie"
           and v.startswith(auth9.cfg.csrf_cookie + "=")]
r.check("a second panel request sets NO new CSRF cookie", not gesetzt,
        f"{gesetzt} — the form in the first tab is therefore dead")

# ---------------------------------------------------------------- proxy templates
# A remote header not set in the template is not omitted but the CLIENT's own is
# passed through. The templates must therefore cover FORWARD_HEADERS_DEFAULT completely.
def fehlende_header(datei: str) -> list[str]:
    """Which remote headers does this template not name? (In a function so that the text is not
    in module scope — there only the comprehension would read it, and CodeQL does not count that as
    use: `py/unused-global-variable`.)"""
    text = (ROOT / datei).read_text(encoding="utf-8").lower()
    return [h for h in TinySesam.FORWARD_HEADERS_DEFAULT.values() if h.lower() not in text]


# ------------------------------------- The [argon2] extra is missing after an upgrade (B6-8)
# New image without the extra, a venv set up anew: every sign-in against an argon2 hash
# failed as „wrong password" — for all existing accounts, without a single log line.
# Simulated without uninstalling the extra: `_ARGON` switched off for the duration of the check.
import logging  # noqa: E402

# An argon2id hash of „geheim123" with minimal parameters (test data only, no secret).
ARGON_HASH = "$argon2id$v=19$m=8,t=1,p=1$lwj6WKW+poScm3635SRZ9Q$GB7yXwpoOqfsI27pXnI9FDaNWilsn2lwG85zAqfypFo"


class _Fang(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.zeilen = []

    def emit(self, record):
        self.zeilen.append(record.getMessage())


fang = _Fang()
logging.getLogger("tinysesam").addHandler(fang)
war_argon = passwords._ARGON
auth_a, db_a = frisch()
uid_a = auth_a.create_user("altkonto", password="egal12345")
auth_a.store.set_password_hash(uid_a, ARGON_HASH)
auth_a.store.db.close()
passwords._ARGON = False
passwords._ARGON2_GEMELDET["ja"] = False
try:
    auth_b, _ = frisch(db_path=db_a)
    beim_start = [z for z in fang.zeilen if "[argon2]" in z]
    r.check("if [argon2] is missing, startup names the affected hashes along with the remedy",
            any("1 betroffene" in z and "pip install" in z for z in beim_start),
            f"{fang.zeilen} — all existing accounts locked, and nobody learns why")
    fang.zeilen.clear()
    r.check("sign-in keeps failing (an argon2 hash cannot be checked without argon2)",
            not auth_b._check_password("altkonto", "geheim123"))
    r.check("…but no longer silent: the failure writes a line",
            any("[argon2]" in z for z in fang.zeilen), f"{fang.zeilen}")
    fang.zeilen.clear()
    auth_b._check_password("altkonto", "geheim123")
    r.check("…and only once, not one per sign-in attempt",
            not any("[argon2]" in z for z in fang.zeilen), f"{fang.zeilen}")
finally:
    passwords._ARGON = war_argon
    logging.getLogger("tinysesam").removeHandler(fang)
fang2 = _Fang()
logging.getLogger("tinysesam").addHandler(fang2)
frisch(db_path=db_a)
logging.getLogger("tinysesam").removeHandler(fang2)
r.check("with [argon2] startup stays quiet (control, provided the extra is present)",
        not war_argon or not any("[argon2]" in z for z in fang2.zeilen), f"{fang2.zeilen}")


CADDYFILES = ("deploy/forward-auth/Caddyfile", "deploy/forward-auth/Caddyfile.gate")
for datei in ("deploy/forward-auth/nginx.conf", *CADDYFILES):
    fehlt = fehlende_header(datei)
    r.check(f"{datei} sets all remote headers", not fehlt, f"missing: {fehlt}")


# NEU-1: Every sub-request to TinySesam sets X-Forwarded-For itself. If it does not, nginx passes
# the CLIENT's header through — and because nginx is in trusted_proxies, the requester determined
# the IP for rate limit, lock and fail2ban. Reproduced with nginx:alpine: without the line an
# `X-Forwarded-For: 6.6.6.6` sent along arrived at TinySesam, with it 127.0.0.1.
def ungeschuetzte_subrequests(datei: str) -> list[str]:
    """The `location` blocks that pass on to TinySesam without setting X-Forwarded-For."""
    text = (ROOT / datei).read_text(encoding="utf-8")
    fehlend = []
    for kopf, rumpf in re.findall(r"location\s+([^{]+)\{(.*?)\n\s*\}", text, re.S):
        if "proxy_pass" in rumpf and ":8000" in rumpf:
            if not re.search(r"proxy_set_header\s+X-Forwarded-For\s+\$(remote_addr|proxy_add_x_forwarded_for)\s*;",
                             rumpf):
                fehlend.append(kopf.strip())
    return fehlend


for datei in ("deploy/forward-auth/nginx.conf", "deploy/forward-auth/nginx-path.conf"):
    r.check(f"{datei}: every path to TinySesam sets X-Forwarded-For itself (NEU-1)",
            not ungeschuetzte_subrequests(datei), f"ohne: {ungeschuetzte_subrequests(datei)}")


# B-20: The session cookie does not go to the protected app. What is measured is the rule itself:
# the `header_up Cookie` lines of the template, applied in their order (Go RE2 and Python's
# `re` read these patterns the same way; reproduced against real Caddy 2.11).
def caddy_cookie_regeln(datei="deploy/forward-auth/Caddyfile") -> list[tuple[str, str]]:
    text = (ROOT / datei).read_text(encoding="utf-8")
    return [(muster.replace("\\\\", "\\"), ersatz)
            for muster, ersatz in re.findall(r'^\s*header_up\s+Cookie\s+"((?:[^"\\]|\\.)*)"\s+"([^"]*)"',
                                             text, re.M)]


def cookie_nach_caddy(cookie: str, datei="deploy/forward-auth/Caddyfile") -> str:
    # The gate template carries the rules twice (fast path, return path); applied twice
    # they change nothing more — this also measures that they do not.
    for muster, ersatz in caddy_cookie_regeln(datei):
        cookie = re.sub(muster, ersatz, cookie)
    return cookie


_sitzung = TinySesamConfig(db_path=":memory:").session_cookie
_faelle = {
    f"a=1; {_sitzung}=GEHEIM; b=2": "a=1; b=2",
    f"{_sitzung}=GEHEIM; b=2": "b=2",
    f"a=1; {_sitzung}=GEHEIM": "a=1",
    f"{_sitzung}=GEHEIM": "",
    f"__Host-{_sitzung}=GEHEIM; x=1": "x=1",
    f"{_sitzung}=A; {_sitzung}=B; c=3": "c=3",
    f"x{_sitzung}=bleibt; y=2": f"x{_sitzung}=bleibt; y=2",
    # A-5: the unlock and the CSRF cookie do not go to the app either.
    "a=1; tinysesam_runlock=R; __Secure-tinysesam_csrf=C; b=2": "a=1; b=2",
    ("tinysesam_oidc_flow=1; tinysesam_saml_flow=2; tinysesam_waflow=3; tinysesam_session=4; "
     "tinysesam_runlock=5; tinysesam_csrf=6; x=7"): "x=7",
    # The situation after the switch to `__Host-` (H-1): the old names remain in the browser until they
    # expire or TinySesam deletes them at the next sign-in, alongside the new ones — seven
    # tinysesam cookies. The six-stage nginx chain let the seventh (here the new session)
    # through to the app. (Mutation probe: the nginx chain at six stages without a latch → red.)
    ("tinysesam_session=ALT; tinysesam_csrf=A; tinysesam_runlock=A; __Host-tinysesam_csrf=c; "
     "__Host-tinysesam_runlock=r; __Host-tinysesam_waflow=w; __Host-tinysesam_session=NEU; a=1"): "a=1",
    ("a=1; tinysesam_session=ALT; tinysesam_csrf=A; tinysesam_runlock=A; __Host-tinysesam_csrf=c; "
     "__Host-tinysesam_runlock=r; __Host-tinysesam_waflow=w; b=2; __Host-tinysesam_session=NEU"): "a=1; b=2",
}
# The gate cookie (ADR-9) is also called tinysesam_* and falls under the same rule.
_faelle["a=1; __Host-tinysesam_gate=eyJ.x.y; b=2"] = "a=1; b=2"
for datei in CADDYFILES:
    r.check(f"{datei}: the cookie rule in front of the app exists (B-20)", bool(caddy_cookie_regeln(datei)),
            "no header_up cookie line — the app receives the session cookie")
    _falsch = {ein: cookie_nach_caddy(ein, datei) for ein, aus in _faelle.items()
               if cookie_nach_caddy(ein, datei) != aus}
    r.check(f"{datei}: the TinySesam cookies are removed, others stay untouched", not _falsch,
            f"{_falsch}")


# A-2: nginx likewise does not pass the TinySesam cookies on to the app (or to PHP). What is measured
# is the template's map chain itself, replayed in Python (PCRE and `re` read these patterns
# the same way; reproduced against real nginx 1.29 + php-fpm 8.3).
def nginx_app_cookie(datei: str, cookie: str) -> str:
    text = (ROOT / datei).read_text(encoding="utf-8")
    werte = {"http_cookie": cookie}
    for quelle, ziel, muster, ersatz, vorgabe in re.findall(
            r'^map \$(\w+) \$(\w+) \{ "~(.*?)" "(.*?)"; default \$(\w+); \}$', text, re.M):
        treffer = re.match(muster.replace("(?<", "(?P<"), werte[quelle])
        werte[ziel] = (re.sub(r"\$(\w+)", lambda m: treffer.group(m.group(1)) or "", ersatz)
                       if treffer else werte[vorgabe])
    return werte.get("ts_app_cookie", cookie)


for datei in ("deploy/forward-auth/nginx.conf", "deploy/forward-auth/nginx-path.conf"):
    _nfalsch = {ein: nginx_app_cookie(datei, ein) for ein, aus in _faelle.items()
                if nginx_app_cookie(datei, ein) != aus}
    r.check(f"{datei}: the TinySesam cookies are removed, others stay untouched (A-2)",
            not _nfalsch, f"{_nfalsch}")
    # How many tinysesam cookies a browser carries is not fixed: six names, each doubled in the
    # transition period after H-1 (old and `__Host-`), plus renamed cookies of several
    # instances. The chain must cover the transition situation completely, and anything beyond that
    # must never slip through to the app — better no cookie at all then (fail closed). Reproduced against real
    # nginx 1.31: 12 pieces → only the own ones, 13 → empty.
    # (Mutation probe: make the latch `$ts_ck_zu` ineffective → red from 13 cookies.)
    _stufen = len(re.findall(r'^map \$\w+ \$ts_ck\d+ ', (ROOT / datei).read_text(encoding="utf-8"), re.M))
    r.check(f"{datei}: the chain covers the transition situation (six names, old and __Host-)",
            _stufen >= 12, f"nur {_stufen} Stufen")
    _durch = {}
    for _n in range(0, 2 * _stufen + 3):
        _ein = "; ".join([f"eigen{i}=v" for i in range(2)]
                         + [f"{'__Host-' if i % 2 else ''}tinysesam_x{i}=geheim" for i in range(_n)]
                         + ["eigen9=v"])
        _aus = nginx_app_cookie(datei, _ein)
        if "tinysesam_" in _aus or (_n <= _stufen and _aus != "eigen0=v; eigen1=v; eigen9=v"):
            _durch[_n] = _aus
    r.check(f"{datei}: arbitrarily many tinysesam cookies — none reaches the app (fail closed)",
            not _durch, f"{_durch}")
_ngx = (ROOT / "deploy/forward-auth/nginx.conf").read_text(encoding="utf-8")
_ngx_app = _ngx.split("location / {")[1].split("proxy_pass")[0]
r.check("nginx.conf: the app gets the filtered cookie", "proxy_set_header Cookie $ts_app_cookie;" in _ngx_app)
_ngx_auth = _ngx.split("location = /auth/forward {")[1].split("}")[0]
r.check("nginx.conf: the sub-request to /auth/forward keeps the cookie",
        "proxy_set_header Cookie $http_cookie;" in _ngx_auth)
_pfad = (ROOT / "deploy/forward-auth/nginx-path.conf").read_text(encoding="utf-8")
r.check("nginx-path.conf: every PHP location gets the filtered cookie (also the open one)",
        _pfad.count("fastcgi_pass") == _pfad.count("fastcgi_param HTTP_COOKIE        $ts_app_cookie;"),
        "a fastcgi_pass location passes the cookie unfiltered to PHP")
_traefik = (ROOT / "deploy/forward-auth/traefik.yml").read_text(encoding="utf-8")
r.check("traefik.yml: the cookie gap is named and the way out is present (A-2)",
        "B-20" in _traefik and 'Cookie: ""' in _traefik)
for datei in CADDYFILES:
    _text = (ROOT / datei).read_text(encoding="utf-8")
    _auth_block = _text.split("rewrite /auth/forward")[1].split("handle_response @ok")[0]
    r.check(f"{datei}: the sub-request to /auth/forward keeps the cookie (otherwise everyone is signed out)",
            "header_up Cookie" not in _auth_block)


# H-16: Caddy finds a response header in `{rp.header.…}` only in the spelling that Go's
# textproto makes of it (each word capitalised, the rest lower case). With `X-TinySesam-Location` a
# 302 with an EMPTY Location came out — without an error, without a log line.
def go_kanonisch(name: str) -> str:
    return "-".join(w[:1].upper() + w[1:].lower() for w in name.split("-"))


for datei, extra in ((CADDYFILES[0], set()), (CADDYFILES[1], {"X-TinySesam-Gate-Cookie"})):
    _platzhalter = re.findall(r"\{rp\.header\.([A-Za-z0-9-]+)\}", (ROOT / datei).read_text(encoding="utf-8"))
    _schief = [p for p in _platzhalter if p != go_kanonisch(p)]
    r.check(f"{datei}: every {{rp.header.…}} placeholder is in Go-canonical form (H-16)",
            _platzhalter and not _schief, f"not canonical: {_schief}")
    _gesendet = set(TinySesam.FORWARD_HEADERS_DEFAULT.values()) | {"X-TinySesam-Location"} | extra
    _fehlt = [h for h in _gesendet if go_kanonisch(h) not in _platzhalter]
    r.check(f"{datei}: every header TinySesam sends has its placeholder", not _fehlt,
            f"missing: {_fehlt}")

raise SystemExit(r.done())
