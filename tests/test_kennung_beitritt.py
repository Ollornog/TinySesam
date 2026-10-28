"""Limit a in full: an identifier belongs to the account from its JOINING, not from creation (G2).

Limit a from the integration attack fixed the creation of the account as the limit: failed attempts and
audit rows from before do not belong to the account. But an account also gets name and address later
— on rename, on address change, on the addition of an address. Until 2026-09-26 the first
full sign-in afterwards cleared the failed attempts that a stranger had made earlier under the then free identifier,
also from the throttling of his IP; the account page showed the sign-in of the
previous owner including his IP, and deleting rewrote his rows. The limit is now an
id watermark per identifier (`users.name_versuch_ab` …): exact even in the second of joining.

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

r = Report("Beitritt einer Kennung — Grenze a für Umbenennen, Adresswechsel, Löschen")
PW = "Beitritt-Test-7"
BASIS = "http://testserver"
SPRAYER, EIGEN = "203.0.113.9", "198.51.100.30"


def _app(db_path=None, **cfg):
    post: list = []
    grund = dict(db_path=db_path or str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, passkey_enabled=False, base_url=BASIS, lang="de")
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    auth.set_mailer(lambda to, betreff, text, html=None: post.append((to, betreff, text)))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, post


def _login(app, name, ip="testclient"):
    return TestClient(app, client=(ip, 1)).post("/auth/login", data={"username": name, "password": PW},
                                                follow_redirects=False)


def _fehlversuche(auth, kennung, ip, n, vorher=0):
    """`n` failed attempts under `kennung` from `ip` — via the path of the routes (with pre-booking of the
    series) —, dated `vorher` seconds back."""
    for _ in range(n):
        v = auth._versuch_beginnen(kennung, ip, "password")
        auth._record_login(kennung, ip, False, "password", versuch=v)
    if vorher:
        auth.store._exec("UPDATE login_attempt SET ts = ts - ? WHERE ip = ?", (vorher, ip))


def _zeile(auth, uid):
    return auth.store.get_user(uid)


# ── a: Umbenennen ────────────────────────────────────────────────────────────────────────────────
# (Mutation probes: in `lift_lockout` only `seit` instead of `ab_id` → red; in `_raeumgrenze` always
#  without limit (`{}`) → red: the sign-in under `frei` then already clears at the first factor.)
a, app, _ = _app()
uid = a.create_user("alt", password=PW)
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_fehlversuche(a, "frei", SPRAYER, 3, vorher=3600)
a.change_username(uid, "frei")
anm = _login(app, "frei")
r.check("a: rename — the failed attempts of a stranger under the then free name remain "
        "after the full sign-in",
        anm.status_code == 303 and a.store.count_fails(0, username="frei") == 3,
        f"HTTP {anm.status_code}, {a.store.count_fails(0, username='frei')}")
r.check("… also in the throttling of HIS IP", a.store.count_fails(0, ip=SPRAYER) == 3,
        str(a.store.count_fails(0, ip=SPRAYER)))
_fehlversuche(a, "frei", EIGEN, 2)
_login(app, "frei")
r.check("… the own ones after the rename are cleared by the sign-in as before",
        a.store.count_fails(0, ip=EIGEN) == 0 and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"{a.store.count_fails(0, ip=EIGEN)} / {a.store.count_fails(0, ip=SPRAYER)}")

# ── b: address change via the real link, and the addition of an address (OIDC) ───────────────
# (Mutation probe: do not set the watermarks in `_kennung_setzen` → both red.)
a, app, post = _app()
uid = a.create_user("mia", password=PW, email="mia@example.com")
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_fehlversuche(a, "neu@example.com", SPRAYER, 2, vorher=3600)
a.request_email_change(uid, "neu@example.com", BASIS)()
a._hinweis_ausgang.abwarten()
link = next((t.group(1) for ziel, _b, text in post if ziel == "neu@example.com"
             for t in [re.search(re.escape(BASIS) + r"(/auth/email/\S+)", text)] if t), "")
bestaetigt = TestClient(app).post(link, follow_redirects=False) if link else None
anm = _login(app, "neu@example.com")
r.check("b: address change via the link — the failed attempts under the new address from before remain",
        bestaetigt is not None and bestaetigt.status_code == 303 and a.get_user(uid)["email"] == "neu@example.com"
        and anm.status_code == 303 and a.store.count_fails(0, username="neu@example.com") == 2,
        f"Link {bool(link)}, HTTP {anm.status_code}, {a.store.count_fails(0, username='neu@example.com')}")
_fehlversuche(a, "nachtrag@example.com", "203.0.113.10", 2, vorher=3600)
a.store.set_email(uid, "nachtrag@example.com", verified=True)      # the path of the OIDC addition
_login(app, "mia")
r.check("… likewise on the addition of an address (store.set_email, the path of OIDC)",
        a.store.count_fails(0, username="nachtrag@example.com") == 2,
        str(a.store.count_fails(0, username="nachtrag@example.com")))

# ── c: the second of creation ─────────────────────────────────────────────────────────────────
# A timestamp cannot decide whether an attempt of the same second came before or after the creation;
# the id can. (Mutation probe: `kennung_grenzen` always returns None → fallback to the
# creation with `ts >= seit` → red.)
a, app, _ = _app()
_fehlversuche(a, "sek@example.com", SPRAYER, 1)
uid = a.create_user("sek", password=PW, email="sek@example.com")
a.store._exec("UPDATE login_attempt SET ts = (SELECT created_at FROM users WHERE id = ?) WHERE ip = ?",
              (uid, SPRAYER))
anm = _login(app, "sek@example.com")
r.check("c: a foreign failed attempt from the second of creation, but BEFORE it, remains",
        anm.status_code == 303 and a.store.count_fails(0, username="sek@example.com") == 1,
        f"HTTP {anm.status_code}, {a.store.count_fails(0, username='sek@example.com')}")

# ── d: counter-check — no overcorrection ──────────────────────────────────────────────────────
# (Mutation probe: watermark + 1 in `WL_VERSUCH` → red; that also keeps out a time-dependent version
#  with `ts > seit`, which would leave own attempts of the same second standing.)
a, app, _ = _app()
a.create_user("sofort", password=PW, email="sofort@example.com")
_fehlversuche(a, "sofort", EIGEN, 1)
_fehlversuche(a, "sofort@example.com", EIGEN, 1)
anm = _login(app, "sofort")
r.check("d: own failed attempts directly after creation (same second) are cleared by the full sign-in",
        anm.status_code == 303 and a.store.count_fails(0, ip=EIGEN) == 0, str(a.store.count_fails(0, ip=EIGEN)))

# ── e: only the spelling changed ──────────────────────────────────────────────────────────────
# The same identifier in the counting bucket — the limit stays. The recalculation trigger cannot tell an own
# writer from a foreign one; `_kennung_setzen` makes sure it does not
# fire here. (Mutation probes: leave out the CASE for the watermark → red; leave the bucket in the first
# statement instead of NULL → the trigger fires and raises the watermark → red.)
a, app, _ = _app()
uid = a.create_user("Gross", password=PW, email="gross@example.com")
vorher = _zeile(a, uid)
_fehlversuche(a, "jemand-anders", SPRAYER, 2)
a.store.audit_log("probe", "jemand-anders")
a.change_username(uid, "gross")
a.store.set_email(uid, "GROSS@example.com", verified=True)
nachher = _zeile(a, uid)
_spalten = ("name_versuch_ab", "name_audit_ab", "mail_versuch_ab", "mail_audit_ab")
r.check("e: renaming only in upper/lower case (name and address) moves no watermark",
        all(vorher[s] is not None and vorher[s] == nachher[s] for s in _spalten)
        and nachher["username"] == "gross" and nachher["topf_name"] == "gross"
        and nachher["topf_mail"] == "gross@example.com",
        f"{[vorher[s] for s in _spalten]} → {[nachher[s] for s in _spalten]}, Topf {nachher['topf_name']!r}")
a.change_username(uid, "gross-neu")
neu_z = _zeile(a, uid)
r.check("… a new name sets it to the current state",
        neu_z["name_versuch_ab"] == a.store._one("SELECT MAX(id) AS m FROM login_attempt")["m"]
        and neu_z["name_audit_ab"] is not None and neu_z["name_audit_ab"] > vorher["name_audit_ab"]
        and neu_z["mail_versuch_ab"] == vorher["mail_versuch_ab"],
        str(dict(neu_z)))

# ── f: deleting after the rename ─────────────────────────────────────────────────────────────
# (Mutation probe: `konto_entfernen` passes no `ab_ids` to `delete_attempts_for` → red.)
a, app, _ = _app()
uid = a.create_user("fx", password=PW)
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_fehlversuche(a, "fneu", SPRAYER, 2, vorher=3600)
a.change_username(uid, "fneu")
_fehlversuche(a, "fneu", EIGEN, 2)
a.delete_user(uid)
r.check("f: deleting after the rename — the stranger's attempts under the new name remain, "
        "the own ones go",
        a.store.count_fails(0, ip=SPRAYER) == 2 and a.store.count_fails(0, ip=EIGEN) == 0,
        f"{a.store.count_fails(0, ip=SPRAYER)} / {a.store.count_fails(0, ip=EIGEN)}")

# ── g: takeover of a freed name — account page and audit ─────────────────────────────────────
# (Mutation probes: `own_events` only with `anlage_grenze` → red; `konto_entfernen` passes no
#  `ab_ids` an `audit_anonymisieren` → rot.)
a, app, _ = _app()
b = a.create_user("bert", password=PW)
a.store._exec("UPDATE users SET created_at = created_at - 100 WHERE id = ?", (b,))
x = a.create_user("xaver", password=PW)
_login(app, "xaver", ip="198.51.100.77")
a.change_username(x, "xaver-neu")
a.change_username(b, "xaver")
eigene = a.own_events(b)
r.check("g: whoever takes over a free name does not see the sign-in of the "
        "previous owner (including his IP) on the account page",
        not any(e["ip"] == "198.51.100.77" or e["event"] == "login" for e in eigene)
        and any(e["event"] == "username_changed" for e in eigene), str(eigene))
a.delete_user(b)
r.check("… and his deleting does not rewrite the previous owner's rows",
        a.store._one("SELECT username FROM audit WHERE event='login' AND ip='198.51.100.77'")["username"] == "xaver",
        str([dict(z) for z in a.store._all("SELECT event, username, ip FROM audit")]))

# ── h: existing data without watermark ───────────────────────────────────────────────────────
# A file from before this column (schema 11 without it; the later
# `name_selbst_gewaehlt`, G2-N, behind it is recorded along): the columns are added and stay NULL,
# the limit is then the creation as before. (Mutation probes: the fallback in `lift_lockout`
# clears from id 0 instead of from the creation → red; likewise in `_raeumgrenze` → red.)
_bestand = str(Path(tempfile.mkdtemp()) / "t.db")
_alt_schema, _n_users = re.subn(r"(idp_bestaetigt_at INTEGER), (--[^\n]*)\n\s*-- Ab wann gehört die Kennung.*?"
                                r"mail_audit_ab\s+INTEGER,\n.*?name_selbst_gewaehlt INTEGER NOT NULL DEFAULT 0\n",
                                r"\1  \2\n", SCHEMA, flags=re.S)
_alt_schema, _n_fi = re.subn(r"\n\s*-- Der Name, unter dem sich das Konto zuletzt.*?name_topf\s+TEXT,", "",
                             _alt_schema, flags=re.S)
os.close(os.open(_bestand, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
_roh = sqlite3.connect(_bestand)
_roh.executescript(_alt_schema)
_jetzt = int(time.time())
_roh.execute("INSERT INTO users(username, email, created_at) VALUES ('bestand', 'bestand@example.com', ?)",
             (_jetzt - 1800,))
_roh.executemany("INSERT INTO login_attempt(ts, username, ip, success, method) VALUES (?, ?, ?, 0, 'password')",
                 [(_jetzt - 3600, "bestand@example.com", SPRAYER)] * 3
                 + [(_jetzt - 60, "bestand@example.com", EIGEN)] * 2)
_roh.execute(f"PRAGMA user_version = {Store.SCHEMA_VERSION}")
_roh.commit()
_roh.close()
a, app, _ = _app(db_path=_bestand)
_uid = a.store.get_user_by_name("bestand")["id"]
a.set_password(_uid, PW)
_hb = _zeile(a, _uid)
_fi = {z["name"] for z in a.store.db.execute("PRAGMA table_info(federated_identity)")}
r.check("h: existing data — the columns are added and stay NULL (no limit invented)",
        _n_users == 1 and _n_fi == 1 and all(_hb[s] is None for s in _spalten) and "name_topf" in _fi,
        f"Schnitt {_n_users}/{_n_fi}, {[_hb[s] for s in _spalten]}, {_fi}")
anm = _login(app, "bestand@example.com")
r.check("… limit is then the creation as before: foreign data from before remains, own data goes",
        anm.status_code == 303 and a.store.count_fails(0, ip=SPRAYER) == 3 and a.store.count_fails(0, ip=EIGEN) == 0,
        f"HTTP {anm.status_code}, {a.store.count_fails(0, ip=SPRAYER)} / {a.store.count_fails(0, ip=EIGEN)}")
a2, _, _ = _app(db_path=_bestand)
_zweit = _zeile(a2, _uid)
_trigger = a2.store._all("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'trg_users_topf_%'")
r.check("… a second start changes nothing (idempotent, trigger once each)",
        all(_zweit[s] is None for s in _spalten) and len(_trigger) == 2, f"{dict(_zweit)} {len(_trigger)}")

# ── i: a foreign writer (raw SQL, older version) ──────────────────────────────────────────────
# The recalculation trigger raises the watermarks — the stricter direction. (Mutation probe: the
# trigger in the version of G12c, only `topf = NULL` → red.)
a, app, _ = _app()
uid = a.create_user("roh-alt", password=PW, email="roh@example.com")
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_fehlversuche(a, "roh-neu", SPRAYER, 3, vorher=3600)
a.store.audit_log("probe", "roh-neu")
a.store._exec("UPDATE users SET username = 'roh-neu' WHERE id = ?", (uid,))
a.store._exec("UPDATE users SET email = 'roh2@example.com' WHERE id = ?", (uid,))
_ri = _zeile(a, uid)
_max_v = a.store._one("SELECT MAX(id) AS m FROM login_attempt")["m"]
_max_a = a.store._one("SELECT MAX(id) AS m FROM audit")["m"]
r.check("i: raw UPDATE of name and address → watermarks at the current state, bucket recalculated",
        _ri["name_versuch_ab"] == _max_v == _ri["mail_versuch_ab"] and _ri["name_audit_ab"] == _max_a
        and _ri["mail_audit_ab"] == _max_a and _ri["topf_name"] is None and _ri["topf_mail"] is None,
        f"{dict(_ri)} MAX {_max_v}/{_max_a}")
anm = _login(app, "roh-neu")
r.check("… and the sign-in under the new name leaves the attempts from before standing",
        anm.status_code == 303 and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"HTTP {anm.status_code}, {a.store.count_fails(0, ip=SPRAYER)}")

# A foreign writer that carries the bucket ITSELF — `store.set_email` from 0.20.1 sets address and
# `topf_mail` in ONE statement (review round 2026-09-27, p1-c). The recalculation trigger then does
# not fire (the bucket does change), and until then the watermark stayed at the state of the OLD
# address: the first full sign-in cleared the stranger's failed attempts under the new one, also from
# the throttling of his IP. (Mutation probe: leave out `trg_users_wechsel_mail` → red.)
from tinysesam.store import norm_email, norm_kennung  # noqa: E402

a, app, _ = _app()
uid = a.create_user("mia", password=PW, email="mia@example.com")
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_fehlversuche(a, "neu@example.com", SPRAYER, 3, vorher=3600)
_wl_c = _zeile(a, uid)["mail_versuch_ab"]
_neu_c = norm_email("neu@example.com")
a.store._exec("UPDATE users SET email=?, email_verified=?, topf_mail=? WHERE id=?",
              (_neu_c, 1, norm_kennung(_neu_c), uid))
_rc = _zeile(a, uid)
anm = _login(app, "neu@example.com")
r.check("i: the writer from 0.20.1 (address and bucket in one statement) raises the watermark too — "
        "the failed attempts under the new address remain",
        _rc["mail_versuch_ab"] == a.store._one("SELECT MAX(id) AS m FROM login_attempt")["m"] > _wl_c
        and _rc["topf_mail"] == "neu@example.com" and anm.status_code == 303
        and a.store.count_fails(0, username="neu@example.com") == 3 and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"WL {_wl_c} → {_rc['mail_versuch_ab']}, HTTP {anm.status_code}, {a.store.count_fails(0, ip=SPRAYER)}")
# Counter-checks: the addition (only the bucket, NULL → bucket) and the own rewrite `B1` → `b1` (the same
# Topf) verschieben nichts.
_vor_n = (_rc["name_versuch_ab"], _rc["mail_versuch_ab"])
_fehlversuche(a, "anderswo", SPRAYER, 1)                 # otherwise the high-water mark would already stand there
a.store._exec("UPDATE users SET topf_name = NULL WHERE id = ?", (uid,))
a.store._exec("UPDATE users SET topf_name = ? WHERE id = ?", ("mia", uid))
a.store.set_username(uid, "MIA")
_rn = _zeile(a, uid)
r.check("… the addition of a bucket and `mia` → `MIA` (the same bucket) leave the watermarks standing",
        (_rn["name_versuch_ab"], _rn["mail_versuch_ab"]) == _vor_n and _rn["topf_name"] == "mia",
        f"{_vor_n} → {(_rn['name_versuch_ab'], _rn['mail_versuch_ab'])}")

# ── j: the series (B2-6) ─────────────────────────────────────────────────────────────────────
# Deliberately WITHOUT limit a (reasoning in `lift_lockout`): the series has no IP, and before the
# join it protected no account. A limit in time would leave a series begun before the join
# unendable for the new owner. (Mutation probe: `fehlserie_loeschen(…, arten=())` → red.)
a, app, _ = _app()
_fehlversuche(a, "serie@example.com", SPRAYER, 3, vorher=3600)
uid = a.create_user("serienkonto", password=PW, email="serie@example.com")
serie_vorher = a.store.fehlserie("serie@example.com")
_login(app, "serienkonto")
r.check("j: the series under the address from before creation ends with the first full sign-in",
        serie_vorher == 3 and a.store.fehlserie("serie@example.com") == 0
        and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"{serie_vorher} → {a.store.fehlserie('serie@example.com')}, Fenster {a.store.count_fails(0, ip=SPRAYER)}")

sys.exit(r.done())
