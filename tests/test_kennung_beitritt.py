"""Grenze a vollständig: Eine Kennung gehört dem Konto ab ihrem BEITRITT, nicht ab der Anlage (G2).

Grenze a aus dem Integrationsangriff hielt die Anlage des Kontos als Grenze fest: Fehlversuche und
Audit-Zeilen von davor gehören nicht dem Konto. Ein Konto bekommt Name und Adresse aber auch später
— beim Umbenennen, beim Adresswechsel, beim Nachtrag einer Adresse. Bis 2026-09-26 räumte die erste
volle Anmeldung danach die Fehlversuche, die ein Fremder vorher unter der damals freien Kennung
gemacht hatte, auch aus der Drosselung seiner IP; die Kontoseite zeigte die Anmeldung des
Vorbesitzers samt dessen IP, und das Löschen schrieb dessen Zeilen um. Die Grenze ist jetzt eine
Id-Wasserlinie je Kennung (`users.name_versuch_ab` …): exakt auch in der Sekunde des Beitritts.

a  Umbenennen          f  Löschen nach dem Umbenennen
b  Adresswechsel       g  Kontoseite und Audit nach Übernahme eines freien Namens
c  Sekunde der Anlage  h  Bestand ohne Wasserlinie: wie bisher (Anlage)
d  eigene Fehlversuche i  fremder Schreiber (rohes SQL): Wasserlinie auf den aktuellen Stand
e  nur Schreibweise    j  die Serie (B2-6) wird bewusst ganz geräumt
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
    """`n` Fehlversuche unter `kennung` von `ip` — über den Weg der Routen (mit Vorbuchung der
    Serie) —, datiert `vorher` Sekunden zurück."""
    for _ in range(n):
        v = auth.versuch_beginnen(kennung, ip, "password")
        auth.record_login(kennung, ip, False, "password", versuch=v)
    if vorher:
        auth.store._exec("UPDATE login_attempt SET ts = ts - ? WHERE ip = ?", (vorher, ip))


def _zeile(auth, uid):
    return auth.store.get_user(uid)


# ── a: Umbenennen ────────────────────────────────────────────────────────────────────────────────
# (Mutationsproben: in `sperre_aufheben` nur `seit` statt `ab_id` → rot; in `_raeumgrenze` immer
#  ohne Grenze (`{}`) → rot: die Anmeldung unter `frei` räumt dann schon beim ersten Faktor.)
a, app, _ = _app()
uid = a.create_user("alt", password=PW)
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_fehlversuche(a, "frei", SPRAYER, 3, vorher=3600)
a.change_username(uid, "frei")
anm = _login(app, "frei")
r.check("a: Umbenennen — die Fehlversuche eines Fremden unter dem damals freien Namen bleiben "
        "nach der vollen Anmeldung stehen",
        anm.status_code == 303 and a.store.count_fails(0, username="frei") == 3,
        f"HTTP {anm.status_code}, {a.store.count_fails(0, username='frei')}")
r.check("… auch in der Drosselung SEINER IP", a.store.count_fails(0, ip=SPRAYER) == 3,
        str(a.store.count_fails(0, ip=SPRAYER)))
_fehlversuche(a, "frei", EIGEN, 2)
_login(app, "frei")
r.check("… die eigenen nach dem Umbenennen räumt die Anmeldung wie bisher",
        a.store.count_fails(0, ip=EIGEN) == 0 and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"{a.store.count_fails(0, ip=EIGEN)} / {a.store.count_fails(0, ip=SPRAYER)}")

# ── b: Adresswechsel über den echten Link, und der Nachtrag einer Adresse (OIDC) ──────────────────
# (Mutationsprobe: in `_kennung_setzen` die Wasserlinien nicht setzen → beide rot.)
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
r.check("b: Adresswechsel über den Link — die Fehlversuche unter der neuen Adresse von davor bleiben",
        bestaetigt is not None and bestaetigt.status_code == 303 and a.get_user(uid)["email"] == "neu@example.com"
        and anm.status_code == 303 and a.store.count_fails(0, username="neu@example.com") == 2,
        f"Link {bool(link)}, HTTP {anm.status_code}, {a.store.count_fails(0, username='neu@example.com')}")
_fehlversuche(a, "nachtrag@example.com", "203.0.113.10", 2, vorher=3600)
a.store.set_email(uid, "nachtrag@example.com", verified=True)      # der Weg des OIDC-Nachtrags
_login(app, "mia")
r.check("… ebenso beim Nachtrag einer Adresse (store.set_email, der Weg von OIDC)",
        a.store.count_fails(0, username="nachtrag@example.com") == 2,
        str(a.store.count_fails(0, username="nachtrag@example.com")))

# ── c: die Sekunde der Anlage ─────────────────────────────────────────────────────────────────────
# Ein Zeitstempel kann nicht entscheiden, ob ein Versuch derselben Sekunde vor oder nach der Anlage
# kam; die Id kann es. (Mutationsprobe: `kennung_grenzen` liefert immer None → Rückfall auf die
# Anlage mit `ts >= seit` → rot.)
a, app, _ = _app()
_fehlversuche(a, "sek@example.com", SPRAYER, 1)
uid = a.create_user("sek", password=PW, email="sek@example.com")
a.store._exec("UPDATE login_attempt SET ts = (SELECT created_at FROM users WHERE id = ?) WHERE ip = ?",
              (uid, SPRAYER))
anm = _login(app, "sek@example.com")
r.check("c: ein fremder Fehlversuch aus der Sekunde der Anlage, aber VOR ihr, bleibt stehen",
        anm.status_code == 303 and a.store.count_fails(0, username="sek@example.com") == 1,
        f"HTTP {anm.status_code}, {a.store.count_fails(0, username='sek@example.com')}")

# ── d: Gegenprobe — keine Überkorrektur ──────────────────────────────────────────────────────────
# (Mutationsprobe: Wasserlinie + 1 in `WL_VERSUCH` → rot; das hält auch eine zeitabhängige Fassung
#  mit `ts > seit` draussen, die eigene Versuche derselben Sekunde stehen liesse.)
a, app, _ = _app()
uid = a.create_user("sofort", password=PW, email="sofort@example.com")
_fehlversuche(a, "sofort", EIGEN, 1)
_fehlversuche(a, "sofort@example.com", EIGEN, 1)
anm = _login(app, "sofort")
r.check("d: eigene Fehlversuche direkt nach der Anlage (dieselbe Sekunde) räumt die volle Anmeldung",
        anm.status_code == 303 and a.store.count_fails(0, ip=EIGEN) == 0, str(a.store.count_fails(0, ip=EIGEN)))

# ── e: nur die Schreibweise geändert ─────────────────────────────────────────────────────────────
# Dieselbe Kennung im Zähl-Topf — die Grenze bleibt. Der Nachrechnen-Trigger kann einen eigenen
# Schreiber nicht von einem fremden unterscheiden; `_kennung_setzen` sorgt dafür, dass er hier nicht
# feuert. (Mutationsproben: den CASE für die Wasserlinie weglassen → rot; den Topf in der ersten
# Anweisung stehen lassen statt NULL → der Trigger feuert und hebt die Wasserlinie → rot.)
a, app, _ = _app()
uid = a.create_user("Gross", password=PW, email="gross@example.com")
vorher = _zeile(a, uid)
_fehlversuche(a, "jemand-anders", SPRAYER, 2)
a.store.audit_log("probe", "jemand-anders")
a.change_username(uid, "gross")
a.store.set_email(uid, "GROSS@example.com", verified=True)
nachher = _zeile(a, uid)
_spalten = ("name_versuch_ab", "name_audit_ab", "mail_versuch_ab", "mail_audit_ab")
r.check("e: Umbenennen nur in Gross-/Kleinschreibung (Name und Adresse) verschiebt keine Wasserlinie",
        all(vorher[s] is not None and vorher[s] == nachher[s] for s in _spalten)
        and nachher["username"] == "gross" and nachher["topf_name"] == "gross"
        and nachher["topf_mail"] == "gross@example.com",
        f"{[vorher[s] for s in _spalten]} → {[nachher[s] for s in _spalten]}, Topf {nachher['topf_name']!r}")
a.change_username(uid, "gross-neu")
neu_z = _zeile(a, uid)
r.check("… ein neuer Name setzt sie auf den aktuellen Stand",
        neu_z["name_versuch_ab"] == a.store._one("SELECT MAX(id) AS m FROM login_attempt")["m"]
        and neu_z["name_audit_ab"] is not None and neu_z["name_audit_ab"] > vorher["name_audit_ab"]
        and neu_z["mail_versuch_ab"] == vorher["mail_versuch_ab"],
        str(dict(neu_z)))

# ── f: Löschen nach dem Umbenennen ───────────────────────────────────────────────────────────────
# (Mutationsprobe: `konto_entfernen` reicht keine `ab_ids` an `delete_attempts_for` → rot.)
a, app, _ = _app()
uid = a.create_user("fx", password=PW)
a.store._exec("UPDATE users SET created_at = created_at - 7200")
_fehlversuche(a, "fneu", SPRAYER, 2, vorher=3600)
a.change_username(uid, "fneu")
_fehlversuche(a, "fneu", EIGEN, 2)
a.delete_user(uid)
r.check("f: Löschen nach dem Umbenennen — die Versuche des Fremden unter dem neuen Namen bleiben, "
        "die eigenen gehen",
        a.store.count_fails(0, ip=SPRAYER) == 2 and a.store.count_fails(0, ip=EIGEN) == 0,
        f"{a.store.count_fails(0, ip=SPRAYER)} / {a.store.count_fails(0, ip=EIGEN)}")

# ── g: Übernahme eines freigewordenen Namens — Kontoseite und Audit ─────────────────────────────
# (Mutationsproben: `own_events` nur mit `anlage_grenze` → rot; `konto_entfernen` reicht keine
#  `ab_ids` an `audit_anonymisieren` → rot.)
a, app, _ = _app()
b = a.create_user("bert", password=PW)
a.store._exec("UPDATE users SET created_at = created_at - 100 WHERE id = ?", (b,))
x = a.create_user("xaver", password=PW)
_login(app, "xaver", ip="198.51.100.77")
a.change_username(x, "xaver-neu")
a.change_username(b, "xaver")
eigene = a.own_events(b)
r.check("g: wer einen freien Namen übernimmt, sieht auf der Kontoseite nicht die Anmeldung des "
        "Vorbesitzers (samt dessen IP)",
        not any(e["ip"] == "198.51.100.77" or e["event"] == "login" for e in eigene)
        and any(e["event"] == "username_changed" for e in eigene), str(eigene))
a.delete_user(b)
r.check("… und sein Löschen schreibt die Zeilen des Vorbesitzers nicht um",
        a.store._one("SELECT username FROM audit WHERE event='login' AND ip='198.51.100.77'")["username"] == "xaver",
        str([dict(z) for z in a.store._all("SELECT event, username, ip FROM audit")]))

# ── h: Bestand ohne Wasserlinie ──────────────────────────────────────────────────────────────────
# Eine Datei von vor dieser Spalte (Schema 11 ohne sie): Die Spalten kommen dazu und bleiben NULL,
# die Grenze ist dann wie bisher die Anlage. (Mutationsproben: der Rückfall in `sperre_aufheben`
# räumt ab Id 0 statt ab der Anlage → rot; ebenso in `_raeumgrenze` → rot.)
_bestand = str(Path(tempfile.mkdtemp()) / "t.db")
_alt_schema, _n_users = re.subn(r"(idp_bestaetigt_at INTEGER), (--[^\n]*)\n\s*-- Ab wann gehört die Kennung.*?"
                                r"mail_audit_ab\s+INTEGER\n", r"\1  \2\n", SCHEMA, flags=re.S)
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
r.check("h: Bestand — die Spalten kommen dazu und bleiben NULL (keine Grenze erfunden)",
        _n_users == 1 and _n_fi == 1 and all(_hb[s] is None for s in _spalten) and "name_topf" in _fi,
        f"Schnitt {_n_users}/{_n_fi}, {[_hb[s] for s in _spalten]}, {_fi}")
anm = _login(app, "bestand@example.com")
r.check("… Grenze ist dann wie bisher die Anlage: Fremdes von davor bleibt, Eigenes geht",
        anm.status_code == 303 and a.store.count_fails(0, ip=SPRAYER) == 3 and a.store.count_fails(0, ip=EIGEN) == 0,
        f"HTTP {anm.status_code}, {a.store.count_fails(0, ip=SPRAYER)} / {a.store.count_fails(0, ip=EIGEN)}")
a2, _, _ = _app(db_path=_bestand)
_zweit = _zeile(a2, _uid)
_trigger = a2.store._all("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'trg_users_topf_%'")
r.check("… ein zweiter Start ändert nichts (idempotent, Trigger je einmal)",
        all(_zweit[s] is None for s in _spalten) and len(_trigger) == 2, f"{dict(_zweit)} {len(_trigger)}")

# ── i: ein fremder Schreiber (rohes SQL, ältere Fassung) ─────────────────────────────────────────
# Der Nachrechnen-Trigger hebt die Wasserlinien — die strengere Richtung. (Mutationsprobe: der
# Trigger in der Fassung von G12c, nur `topf = NULL` → rot.)
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
r.check("i: rohes UPDATE von Name und Adresse → Wasserlinien auf dem aktuellen Stand, Topf nachzurechnen",
        _ri["name_versuch_ab"] == _max_v == _ri["mail_versuch_ab"] and _ri["name_audit_ab"] == _max_a
        and _ri["mail_audit_ab"] == _max_a and _ri["topf_name"] is None and _ri["topf_mail"] is None,
        f"{dict(_ri)} MAX {_max_v}/{_max_a}")
anm = _login(app, "roh-neu")
r.check("… und die Anmeldung unter dem neuen Namen lässt die Versuche von davor stehen",
        anm.status_code == 303 and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"HTTP {anm.status_code}, {a.store.count_fails(0, ip=SPRAYER)}")

# ── j: die Serie (B2-6) ──────────────────────────────────────────────────────────────────────────
# Bewusst OHNE Grenze a (Begründung in `sperre_aufheben`): Die Serie hat keine IP, und vor dem
# Beitritt schützte sie kein Konto. Eine Grenze in der Zeit liesse eine vor dem Beitritt begonnene
# Serie für den neuen Inhaber unbeendbar. (Mutationsprobe: `fehlserie_loeschen(…, arten=())` → rot.)
a, app, _ = _app()
_fehlversuche(a, "serie@example.com", SPRAYER, 3, vorher=3600)
uid = a.create_user("serienkonto", password=PW, email="serie@example.com")
serie_vorher = a.store.fehlserie("serie@example.com")
_login(app, "serienkonto")
r.check("j: die Serie unter der Adresse von vor der Anlage endet mit der ersten vollen Anmeldung",
        serie_vorher == 3 and a.store.fehlserie("serie@example.com") == 0
        and a.store.count_fails(0, ip=SPRAYER) == 3,
        f"{serie_vorher} → {a.store.fehlserie('serie@example.com')}, Fenster {a.store.count_fails(0, ip=SPRAYER)}")

sys.exit(r.done())
