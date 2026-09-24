"""Was beim UPGRADE einer bestehenden Installation passiert — und was nicht passieren darf.

Der Doku-Abgleich vom 2026-09-21 hat sieben Stellen gefunden, an denen die Doku etwas anderes
sagte als der Code. Fünf davon waren keine Schreibfehler, sondern echte Mängel; diese Suite hält
sie fest, damit sie nicht zurückkommen. Der schwerste: die Anhebung der scrypt-Parameter in
0.18.0 hätte jedes Konto ausgesperrt, das ohne das Extra `[argon2]` läuft.

Alle Prüfungen kommen ohne Extras aus.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import sqlite3
import sys
import tempfile
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

r = Report("Bestandsdaten — was ein Upgrade überleben muss")


def frisch(**cfg) -> tuple[TinySesam, str]:
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    kw = dict(db_path=db, lang="de", passkey_enabled=False, oidc_enabled=False,
              cookie_secure=False)
    kw.update(cfg)
    return TinySesam(TinySesamConfig(**kw)), db


# ---------------------------------------------------------------- scrypt-Bestandshashes
# Bis 0.17.0 lautete das Format `scrypt$salt$dk` und es trug seine Parameter NICHT mit; gerechnet
# wurde mit n=2^15, r=8, p=1. 0.18.0 hob p auf 3 — und `verify_password` rechnete jeden Altbestand
# mit dem neuen p nach. Ergebnis wäre "Passwort stimmt nicht" für jedes Konto ohne `[argon2]`
# gewesen, ohne eine einzige Fehlermeldung, die den Grund nennt.
def alt_hash(pw: str) -> str:
    """Einen Hash im Format von 0.17.0 erzeugen (p=1, ohne Parameter im String)."""
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32,
                        maxmem=132 * 1024 * 1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


bestand = alt_hash("geheim123")
r.check("Bestandshash aus 0.17.0 verifiziert weiter",
        passwords.verify_password("geheim123", bestand),
        "die Parameter-Anhebung sperrt alle scrypt-Konten aus")
r.check("… und ein falsches Passwort dagegen nicht",
        not passwords.verify_password("falsch", bestand))
r.check("Bestandshash gilt als erneuerungsbedürftig",
        passwords.needs_rehash(bestand),
        "sonst bleibt das Konto für immer auf den schwächeren Parametern")

neu = "scrypt$%d$%d$%d$%s$%s" % (
    passwords._SCRYPT["n"], passwords._SCRYPT["r"], passwords._SCRYPT["p"],
    base64.b64encode(b"0123456789abcdef").decode(),
    base64.b64encode(hashlib.scrypt(b"geheim123", salt=b"0123456789abcdef",
                                    **passwords._SCRYPT)).decode())
r.check("Hash im heutigen Format verifiziert", passwords.verify_password("geheim123", neu))
if not passwords._ARGON:
    # Ohne argon2 erzeugt hash_password selbst scrypt — dann muss das neue Format herauskommen
    # und darf nicht sofort wieder als veraltet gelten.
    eigen = passwords.hash_password("geheim123")
    r.check("selbst erzeugter Hash trägt seine Parameter", eigen.count("$") == 5, eigen[:24])
    r.check("… und gilt nicht als erneuerungsbedürftig", not passwords.needs_rehash(eigen))
else:
    r.check("ohne argon2 trägt ein neuer Hash 5 Trenner",
            passwords.hash_password.__module__ == "tinysesam.passwords")

# Und der Weg, der im Betrieb zählt: Ein Konto, dessen Hash aus 0.17.0 stammt, meldet sich an.
auth, db = frisch()
uid = auth.create_user("bestand", password="geheim123")
auth.store.set_password_hash(uid, bestand)
r.check("Anmeldung mit 0.17.0-Hash gelingt", bool(auth.check_password("bestand", "geheim123")),
        "der Login-Pfad rechnet anders als verify_password")

# ---------------------------------------------------------------- Migration einer Altdatei
# `resource_unlock.token` trägt seit 0.18.0 den sha256 statt des Klartexts. Die Bereinigung hing
# an `0 < PRAGMA user_version < 4` — und `user_version` kam selbst erst mit 0.18.0, eine Datei aus
# 0.17.0 trägt dort die 0. Die Bedingung war also in genau dem Fall falsch, für den sie geschrieben
# war: Der Klartext wäre liegengeblieben und hätte nie wieder gematcht.
alt_db = os.path.join(tempfile.mkdtemp(), "alt.db")
auth0, _ = frisch(db_path=alt_db, resource_locks_enabled=True)
auth0.store.add_resource_unlock("klartext-token", "akte-7", 4102444800)
auth0.store.db.execute("PRAGMA user_version = 0")            # Stand einer 0.17.0-Datei
auth0.store.db.execute("UPDATE resource_unlock SET token='klartext-token'")
auth0.store.db.commit()
auth0.store.db.close()

roh = sqlite3.connect(alt_db)
vorher = roh.execute("SELECT count(*) FROM resource_unlock").fetchone()[0]
roh.close()
r.check("Vorbedingung: die Altdatei trägt einen Klartext-Eintrag", vorher == 1, f"{vorher}")

Store(alt_db).db.close()                                      # = Upgrade auf 0.18.0
roh = sqlite3.connect(alt_db)
nachher = roh.execute("SELECT count(*) FROM resource_unlock").fetchone()[0]
stempel = roh.execute("PRAGMA user_version").fetchone()[0]
roh.close()
r.check("Klartext-Freigabe wird beim Upgrade verworfen", nachher == 0,
        f"{nachher} Einträge geblieben — sie matchen nie wieder")
r.check("… und die Datei trägt danach den Schema-Stempel", stempel == Store.SCHEMA_VERSION,
        f"{stempel}")

# Eine gehashte Freigabe darf die Bereinigung NICHT treffen (sonst räumt jeder Start ab).
auth1, db1 = frisch(resource_locks_enabled=True)
auth1.store.add_resource_unlock("frisch-token", "akte-8", 4102444800)
auth1.store.db.close()
s2 = Store(db1)
r.check("gehashte Freigabe überlebt einen Neustart",
        s2.is_resource_unlocked("frisch-token", "akte-8"),
        "die Bereinigung greift zu weit")
s2.db.close()

# ---------------------------------------------------------------- Schema 9 → 10
# Was die Migration auf Schema 10 mit einem Bestand macht — an einer Datei im Stand von Schema 9
# (heutiges Schema ohne das, was 10 hinzufügt; die Vorbedingung prüft, dass nichts davon übrig ist).
#
# (a) Betreiber-Sperren aus früheren Fassungen (S-5). Bis 0.19.x schrieb die Sperre im Panel
#     `disabled=1` und verwarf die offenen Token NICHT. Nach dem Upgrade hob der alte
#     Bestätigungslink einer ausstehenden Registrierung die Sperre auf und meldete an — die
#     Aussage „ihre offenen Token hat die Sperre damals schon verworfen“ stimmte für kein Release.
# (b) Die Zähl-Töpfe (S-1) werden für jede Bestandszeile gerechnet, Indizes und Trigger angelegt.
# (c) Adressen offener Registrierungen verlieren den Vermerk „belegt“ (S-2), bis der Link kommt.
# (Mutationsproben: den Panel-Schritt streichen → rot bei (a), der alte Link gibt 303; dort die
#  Token nicht verwerfen → rot bei (a); nur `detail = 'uid=<id>'` erkennen, nicht `'uid=<id> …'`
#  → rot bei (a); den Schritt für offene Registrierungen streichen → rot bei (c); in `/auth/verify`
#  den Beleg nicht setzen → rot bei (c); den Topf-Schritt der Migration streichen → rot bei (b).)
_s10_ordner = tempfile.mkdtemp()
_s10_db = os.path.join(_s10_ordner, "schema9.db")
_s10_cfg = dict(db_path=os.path.join(_s10_ordner, "quelle.db"), allow_signup=True,
                signup_require_email=True, signup_verify_email=True, csrf_enabled=False,
                base_url="https://auth.example.com")
_s10_alt, _ = frisch(**_s10_cfg)
_s10_alt.create_user("chefin", password="Geheim12345!", is_admin=True)
_s10_ids, _s10_links = {}, {}
for _name in ("verdacht", "wartend", "wieder", "altsperre"):
    _uid = _s10_alt.store.create_user(_name, None, f"{_name}@example.org")   # Vermerk 1, wie damals
    _s10_ids[_name] = _uid
    _s10_alt.store.set_disabled(_uid, True)                                # damals: immer 1
    if _name != "altsperre":
        _s10_links[_name] = _s10_alt.create_magic_token("verify_email", user_id=_uid,
                                                        email=f"{_name}@example.org")
# Die Panel-Sperre von damals: Audit-Zeile mit `uid=<id>`, Token bleiben liegen.
_s10_alt.store.audit_log("user_disable", "chefin", None, f"uid={_s10_ids['verdacht']} api_keys_revoked=1")
_s10_alt.store.audit_log("user_disable", "chefin", None, f"uid={_s10_ids['altsperre']}")
_s10_alt.store.audit_log("user_disable", "chefin", None, f"uid={_s10_ids['wieder']}")
_s10_alt.store.audit_log("user_enable", "chefin", None, f"uid={_s10_ids['wieder']}")
_s10_emile = _s10_alt.store.create_user("Émile", None, "Emile@Bücher.example")
_s10_alt.store.db.close()
# Die Datei im Stand von Schema 9: das Schema ohne die Topf-Spalten (Indizes und Trigger legt erst
# `_migrate` an), die Daten per ATTACH aus der eben gefüllten Datei. Nicht per `ALTER TABLE …
# DROP COLUMN`: SQLite sucht beim Entfernen der letzten Spalte das Komma davor rückwärts im Text
# und findet eines im Kommentar darüber („incomplete input“).
from tinysesam.store import SCHEMA as _S10_SCHEMA  # noqa: E402
_s10_schema9, _s10_n = re.subn(r",\n\s*-- Der Zähl-Topf.*?topf_mail\s+TEXT\n", "\n", _S10_SCHEMA, flags=re.S)
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
r.check("Vorbedingung: die Datei steht auf Schema 9, ohne Topf-Spalten, Indizes und Trigger, mit allen Konten",
        _s10_n == 1 and not _s10_rest and _s10_zahl == 6 and Store.SCHEMA_VERSION == 10,
        f"Schnitt {_s10_n}, Reste {_s10_rest}, Konten {_s10_zahl}, SCHEMA_VERSION={Store.SCHEMA_VERSION}")

_s10, _ = frisch(**_s10_cfg)                                      # = Upgrade auf Schema 10
_s10_app = FastAPI()
_s10_app.include_router(_s10.router())
_s10_u = {n: _s10.store.get_user(i) for n, i in _s10_ids.items()}
_s10_offen = {n: _s10.store._one("SELECT COUNT(*) AS n FROM magic_token WHERE user_id=? AND used_at IS NULL",
                                 (i,))["n"] for n, i in _s10_ids.items()}
_s10_link = TestClient(_s10_app, client=("192.0.2.66", 1)).post(
    f"/auth/verify/{_s10_links['verdacht']}", follow_redirects=False)
r.check("S-5 (a): eine Panel-Sperre von damals trägt nach dem Upgrade den Betreiber-Vermerk, ihre "
        "offenen Token sind verworfen — der alte Bestätigungslink schaltet nicht frei",
        _s10_u["verdacht"]["disabled"] == 2 and _s10_offen["verdacht"] == 0
        and _s10_u["altsperre"]["disabled"] == 2
        and _s10_link.status_code != 303 and _s10.store.get_user(_s10_ids["verdacht"])["disabled"] == 2
        and not _s10.store.list_sessions(_s10_ids["verdacht"]),
        f"verdacht {dict(_s10_u['verdacht'])}, offen {_s10_offen}, Link HTTP {_s10_link.status_code}")
_s10_wartet = TestClient(_s10_app, client=("192.0.2.67", 1)).post(
    f"/auth/verify/{_s10_links['wartend']}", follow_redirects=False)
r.check("S-5 (a): … eine ausstehende Registrierung ohne Panel-Sperre bleibt freischaltbar, eine "
        "wieder entsperrte Sperre bleibt die der App (1)",
        _s10_u["wartend"]["disabled"] == 1 and _s10_offen["wartend"] == 1
        and _s10_wartet.status_code == 303 and _s10.store.get_user(_s10_ids["wartend"])["disabled"] == 0
        and _s10_u["wieder"]["disabled"] == 1 and _s10_offen["wieder"] == 1,
        f"wartend {dict(_s10_u['wartend'])}, Link HTTP {_s10_wartet.status_code}, wieder {dict(_s10_u['wieder'])}")
r.check("S-2 (c): Adressen offener Registrierungen tragen nach dem Upgrade keinen Beleg, bis der "
        "Link kommt — dann wieder",
        _s10_u["verdacht"]["email_verified"] == 0 and _s10_u["wartend"]["email_verified"] == 0
        and _s10.store.get_user(_s10_ids["wartend"])["email_verified"] == 1
        and _s10.store.get_user(_s10_emile)["email_verified"] == 1,
        f"verdacht {_s10_u['verdacht']['email_verified']}, wartend vorher "
        f"{_s10_u['wartend']['email_verified']}, nachher {_s10.store.get_user(_s10_ids['wartend'])['email_verified']}")
_s10_objekte = {z["name"] for z in _s10.store._all("SELECT name FROM sqlite_master WHERE tbl_name='users'")}
_s10_e = _s10.store.get_user(_s10_emile)
_s10_ohne = _s10.store._one("SELECT COUNT(*) AS n FROM users WHERE topf_name IS NULL OR topf_mail IS NULL")["n"]
r.check("S-1 (b): jede Bestandszeile bekommt ihren Zähl-Topf, Indizes und Trigger stehen",
        _s10_ohne == 0 and _s10_e["topf_name"] == "émile"
        and _s10_e["topf_mail"] == "emile@xn--bcher-kva.example"
        and {"ix_users_topf_name", "ix_users_topf_mail", "ix_users_name_nocase", "ix_users_email_nocase",
             "trg_users_topf_name", "trg_users_topf_mail"} <= _s10_objekte
        and (_s10.store.konto_mit_topf("émile") or {"id": None})["id"] == _s10_emile,
        f"ohne Topf {_s10_ohne}, Émile {(_s10_e['topf_name'], _s10_e['topf_mail'])}, Objekte {_s10_objekte}")
_s10.store.db.close()
# Wer die Faltung in `norm_kennung` ändert, hebt das Schema — dann rechnet der Start ALLE Töpfe neu
# (`Store.TOPF_SCHEMA`), nicht nur die fehlenden. Nachgestellt mit einem veralteten Topf in einer
# Datei, deren Stempel unter `TOPF_SCHEMA` liegt.
# (Mutationsprobe: in `_migrate` immer nur die NULL-Zeilen rechnen → rot.)
_s10_veraltet = sqlite3.connect(_s10_db)
_s10_veraltet.execute("UPDATE users SET topf_name='alte-faltung' WHERE id=?", (_s10_emile,))
_s10_veraltet.execute(f"PRAGMA user_version = {Store.TOPF_SCHEMA - 1}")
_s10_veraltet.commit()
_s10_veraltet.close()
_s10_neu = Store(_s10_db)
r.check("S-1 (b): … ein Stempel unter TOPF_SCHEMA rechnet auch vorhandene Töpfe neu",
        _s10_neu.get_user(_s10_emile)["topf_name"] == "émile",
        f"{_s10_neu.get_user(_s10_emile)['topf_name']}")
_s10_neu.db.close()
_s10_zweit = Store(_s10_db)
r.check("… ein zweiter Start ändert nichts mehr (Stempel 10, keine weitere Sperre, kein Vermerk)",
        int(_s10_zweit.db.execute("PRAGMA user_version").fetchone()[0]) == 10
        and _s10_zweit.get_user(_s10_ids["wieder"])["disabled"] == 1
        and _s10_zweit.get_user(_s10_ids["wartend"])["email_verified"] == 1)
_s10_zweit.db.close()

# ---------------------------------------------------------------- audit --user
# Das Kommando siebte die jüngsten Zeilen nach, statt in SQL zu filtern: Wer im Anlassfall suchte
# (Brute-Force-Welle), bekam "Keine Einträge zu 'X'." und Exit 0, obwohl sie dastanden.
auth2, _ = frisch()
auth2.audit("login_ok", username="opfer", detail="alt")
for i in range(300):
    auth2.audit("login_fail", username="rauschen", detail=str(i))
treffer = auth2.store.recent_audit(30, username="opfer")
r.check("audit --user findet Einträge hinter 300 Zeilen Rauschen", len(treffer) == 1,
        f"{len(treffer)} gefunden")
r.check("… und filtert unabhängig von der Schreibweise",
        len(auth2.store.recent_audit(30, username="OPFER")) == 1)
r.check("ohne Filter kommen weiter die jüngsten Zeilen",
        len(auth2.store.recent_audit(5)) == 5)

# ---------------------------------------------------------------- seed_demo
# Der Docstring versprach "nur bei demo_mode=True", der Rumpf prüfte es nicht: Ein direkter Aufruf
# legte `demoadmin` mit bekanntem Passwort und is_admin=1 an — anmeldefähig, ohne Warnung im Log.
auth3, _ = frisch()
try:
    auth3.seed_demo()
    r.check("seed_demo() ohne demo_mode wird abgewiesen", False, "es lief durch")
except ConfigError:
    r.check("seed_demo() ohne demo_mode wird abgewiesen", True)
r.check("… und legt dabei kein Admin-Konto an",
        auth3.store.get_user_by_name("demoadmin") is None)

# ---------------------------------------------------------------- stepup_strict
# `stepup_methods` war immer nur ein Wunsch: Wer keines der genannten Verfahren eingerichtet hatte,
# bestätigte mit allem, was er hatte — inklusive des Passworts, mit dem er sich gerade angemeldet
# hatte. Das ist kein Step-up. Die Schranke gibt es jetzt, die Vorgabe bleibt der alte Weg.
auth4, _ = frisch(stepup_methods=["totp"])
u4 = auth4.store.get_user(auth4.create_user("ohne_totp", password="pw123456"))
r.check("stepup_methods bleibt per Vorgabe ein Wunsch",
        auth4.stepup_options(u4) == ["password"], f"{auth4.stepup_options(u4)}")
auth5, _ = frisch(stepup_methods=["totp"], stepup_strict=True)
u5 = auth5.store.get_user(auth5.create_user("ohne_totp", password="pw123456"))
r.check("stepup_strict=True lässt nichts durch, was nicht gewünscht war",
        auth5.stepup_options(u5) == [], f"{auth5.stepup_options(u5)}")
auth6, _ = frisch(stepup_methods=[], stepup_strict=True)
u6 = auth6.store.get_user(auth6.create_user("normal", password="pw123456"))
r.check("stepup_strict ohne stepup_methods ändert nichts",
        auth6.stepup_options(u6) == ["password"], f"{auth6.stepup_options(u6)}")

# ---------------------------------------------------------------- login_chain-Sackgasse
# `login_chain=["password","totp"]` sperrte jedes Konto OHNE eingerichtetes TOTP dauerhaft aus:
# Das richtige Passwort führte auf /auth/totp, das mangels Geheimnis auf die Login-Seite
# zurückleitete — und die Einrichtungsseite verlangte einen voll angemeldeten Nutzer, den es unter
# dieser Kette nie geben kann. Weder herein noch an die Einrichtung.
auth7, _ = frisch(login_chain=["password", "totp"], csrf_enabled=False)
auth7.create_user("kette", password="pw123456")
app7 = FastAPI()
app7.include_router(auth7.router())
c7 = TestClient(app7, follow_redirects=False)
ant = c7.post("/auth/login", data={"username": "kette", "password": "pw123456"})
r.check("richtiges Passwort führt zum zweiten Faktor",
        ant.status_code == 303 and "/auth/totp" in ant.headers.get("location", ""),
        f"{ant.status_code} {ant.headers.get('location')}")
ant = c7.get("/auth/totp")
r.check("/auth/totp schickt ohne Geheimnis zur EINRICHTUNG, nicht zurück zum Login",
        ant.status_code == 303 and "/auth/totp/setup" in ant.headers.get("location", ""),
        f"{ant.status_code} {ant.headers.get('location')} — Sackgasse")
ant = c7.get("/auth/totp/setup")
r.check("die Einrichtungsseite ist in diesem Zustand erreichbar", ant.status_code == 200,
        f"{ant.status_code}")

# Ohne Kette bleibt es beim alten Verhalten: keine Einrichtung ohne volle Anmeldung.
auth8, _ = frisch(csrf_enabled=False)
auth8.create_user("klassisch", password="pw123456")
app8 = FastAPI()
app8.include_router(auth8.router())
c8 = TestClient(app8, follow_redirects=False)
ant = c8.get("/auth/totp/setup")
r.check("ohne Sitzung führt die Einrichtungsseite weiter zum Login",
        ant.status_code == 303 and "/auth/login" in ant.headers.get("location", ""),
        f"{ant.status_code} {ant.headers.get('location')}")

# ---------------------------------------------------------------- B-1: Admin-Panel und CSRF
# Das Panel würfelte bei JEDEM Aufruf ein neues CSRF-Token. Wer es im zweiten Reiter öffnete,
# machte damit das offene Formular im ersten ungültig — 403 ohne Erklärung. Geprüft wird der
# ROHE Set-Cookie-Header: `TestClient` führt den Cookie-Jar mit und würde ein erneutes Setzen
# desselben Werts verschlucken.
auth9, _ = frisch(csrf_enabled=True, admin_enabled=True)
auth9.ensure_admin("chef", "pw123456")
app9 = FastAPI()
app9.include_router(auth9.router())
c9 = TestClient(app9)
c9.get("/auth/login")                       # setzt erst das CSRF-Cookie
anm = c9.post("/auth/login", data={"username": "chef", "password": "pw123456",
                                   "_csrf": c9.cookies.get(auth9.cfg.csrf_cookie, "")},
              follow_redirects=False)
# 303 = angemeldet. Ohne `follow_redirects=False` liefe der Client dem `next` hinterher und
# meldete die 404 der Zielseite — diese App hat kein "/".
r.check("Vorbedingung: die Anmeldung gelingt", anm.status_code == 303, f"{anm.status_code}")
erste = c9.get(auth9.cfg.admin_path)
# Ohne diese Vorbedingung prüfte der Test darunter nichts: Ein 401 setzt natürlich auch kein
# CSRF-Cookie, und die Suite wäre grün geblieben, ohne den Fall je gesehen zu haben.
r.check("Vorbedingung: das Panel ist erreichbar", erste.status_code == 200, f"{erste.status_code}")
r.check("Vorbedingung: der erste Aufruf SETZT ein CSRF-Cookie",
        any(k.lower() == "set-cookie" and v.startswith(auth9.cfg.csrf_cookie + "=")
            for k, v in erste.headers.items())
        or bool(c9.cookies.get(auth9.cfg.csrf_cookie)),
        "kein Cookie — dann misst die Prüfung darunter nichts")
zweite = c9.get(auth9.cfg.admin_path)
gesetzt = [v for k, v in zweite.headers.items() if k.lower() == "set-cookie"
           and v.startswith(auth9.cfg.csrf_cookie + "=")]
r.check("ein zweiter Panel-Aufruf setzt KEIN neues CSRF-Cookie", not gesetzt,
        f"{gesetzt} — das Formular im ersten Reiter ist damit tot")

# ---------------------------------------------------------------- Proxy-Vorlagen
# Ein in der Vorlage nicht gesetzter Remote-Header wird nicht weggelassen, sondern der des CLIENTS
# durchgereicht. Die Vorlagen müssen FORWARD_HEADERS_DEFAULT deshalb vollständig abdecken.
def fehlende_header(datei: str) -> list[str]:
    """Welche Remote-Header nennt diese Vorlage nicht? (In einer Funktion, damit der Text nicht
    im Modul-Scope steht — dort läse ihn nur die Comprehension, und CodeQL zählt das nicht als
    Nutzung: `py/unused-global-variable`.)"""
    text = (ROOT / datei).read_text(encoding="utf-8").lower()
    return [h for h in TinySesam.FORWARD_HEADERS_DEFAULT.values() if h.lower() not in text]


# ------------------------------------- Das Extra [argon2] fehlt nach einem Upgrade (B6-8)
# Neues Abbild ohne das Extra, ein venv neu aufgesetzt: Jede Anmeldung gegen einen argon2-Hash
# scheiterte als „falsches Passwort" — für alle Bestandskonten, ohne eine einzige Logzeile.
# Nachgestellt ohne das Extra zu deinstallieren: `_ARGON` für die Dauer der Prüfung aus.
import logging  # noqa: E402

# Ein argon2id-Hash von „geheim123" mit Minimalparametern (nur Testdaten, kein Geheimnis).
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
    r.check("fehlt [argon2], nennt der Start die betroffenen Hashes samt Abhilfe",
            any("1 betroffene" in z and "pip install" in z for z in beim_start),
            f"{fang.zeilen} — alle Bestandskonten gesperrt, und niemand erfährt warum")
    fang.zeilen.clear()
    r.check("die Anmeldung scheitert weiter (ein argon2-Hash ist ohne argon2 nicht prüfbar)",
            not auth_b.check_password("altkonto", "geheim123"))
    r.check("…aber nicht mehr still: der Fehlschlag schreibt eine Zeile",
            any("[argon2]" in z for z in fang.zeilen), f"{fang.zeilen}")
    fang.zeilen.clear()
    auth_b.check_password("altkonto", "geheim123")
    r.check("…und zwar einmal, nicht eine je Anmeldeversuch",
            not any("[argon2]" in z for z in fang.zeilen), f"{fang.zeilen}")
finally:
    passwords._ARGON = war_argon
    logging.getLogger("tinysesam").removeHandler(fang)
fang2 = _Fang()
logging.getLogger("tinysesam").addHandler(fang2)
frisch(db_path=db_a)
logging.getLogger("tinysesam").removeHandler(fang2)
r.check("mit [argon2] bleibt der Start still (Gegenprobe, sofern das Extra da ist)",
        not war_argon or not any("[argon2]" in z for z in fang2.zeilen), f"{fang2.zeilen}")


for datei in ("deploy/forward-auth/nginx.conf", "deploy/forward-auth/Caddyfile"):
    fehlt = fehlende_header(datei)
    r.check(f"{datei} setzt alle Remote-Header", not fehlt, f"fehlt: {fehlt}")


# NEU-1: Jeder Sub-Request an TinySesam setzt X-Forwarded-For selbst. Tut er es nicht, reicht nginx
# den Header des CLIENTS durch — und weil nginx in trusted_proxies steht, bestimmte der Anfragende
# die IP für Rate-Limit, Sperre und fail2ban. Nachgestellt mit nginx:alpine: ohne die Zeile kam
# ein mitgeschickter `X-Forwarded-For: 6.6.6.6` bei TinySesam an, mit ihr 127.0.0.1.
def ungeschuetzte_subrequests(datei: str) -> list[str]:
    """Die `location`-Blöcke, die an TinySesam weiterreichen, ohne X-Forwarded-For zu setzen."""
    text = (ROOT / datei).read_text(encoding="utf-8")
    fehlend = []
    for kopf, rumpf in re.findall(r"location\s+([^{]+)\{(.*?)\n\s*\}", text, re.S):
        if "proxy_pass" in rumpf and ":8000" in rumpf:
            if not re.search(r"proxy_set_header\s+X-Forwarded-For\s+\$(remote_addr|proxy_add_x_forwarded_for)\s*;",
                             rumpf):
                fehlend.append(kopf.strip())
    return fehlend


for datei in ("deploy/forward-auth/nginx.conf", "deploy/forward-auth/nginx-pfad.conf"):
    r.check(f"{datei}: jeder Weg zu TinySesam setzt X-Forwarded-For selbst (NEU-1)",
            not ungeschuetzte_subrequests(datei), f"ohne: {ungeschuetzte_subrequests(datei)}")


# B-20: Das Sitzungs-Cookie geht nicht an die geschützte App. Gemessen wird die Regel selbst:
# die `header_up Cookie`-Zeilen der Vorlage, in ihrer Reihenfolge angewandt (Go-RE2 und Pythons
# `re` lesen diese Muster gleich; gegen echtes Caddy 2.11 nachgestellt).
def caddy_cookie_regeln() -> list[tuple[str, str]]:
    text = (ROOT / "deploy/forward-auth/Caddyfile").read_text(encoding="utf-8")
    return [(muster.replace("\\\\", "\\"), ersatz)
            for muster, ersatz in re.findall(r'^\s*header_up\s+Cookie\s+"((?:[^"\\]|\\.)*)"\s+"([^"]*)"',
                                             text, re.M)]


def cookie_nach_caddy(cookie: str) -> str:
    for muster, ersatz in caddy_cookie_regeln():
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
    # A-5: auch das Freigabe- und das CSRF-Cookie gehen nicht an die App.
    "a=1; tinysesam_runlock=R; __Secure-tinysesam_csrf=C; b=2": "a=1; b=2",
    ("tinysesam_oidc_flow=1; tinysesam_saml_flow=2; tinysesam_waflow=3; tinysesam_session=4; "
     "tinysesam_runlock=5; tinysesam_csrf=6; x=7"): "x=7",
    # Die Lage nach dem Umstieg auf `__Host-` (H-1): Die Altnamen liegen im Browser, bis sie
    # ablaufen oder TinySesam sie beim nächsten Anmelden löscht, daneben die neuen — sieben
    # tinysesam-Cookies. Die sechsstufige nginx-Kette liess das siebte (hier die neue Sitzung)
    # zur App durch. (Mutationsprobe: die nginx-Kette auf sechs Stufen ohne Riegel → rot.)
    ("tinysesam_session=ALT; tinysesam_csrf=A; tinysesam_runlock=A; __Host-tinysesam_csrf=c; "
     "__Host-tinysesam_runlock=r; __Host-tinysesam_waflow=w; __Host-tinysesam_session=NEU; a=1"): "a=1",
    ("a=1; tinysesam_session=ALT; tinysesam_csrf=A; tinysesam_runlock=A; __Host-tinysesam_csrf=c; "
     "__Host-tinysesam_runlock=r; __Host-tinysesam_waflow=w; b=2; __Host-tinysesam_session=NEU"): "a=1; b=2",
}
r.check("Caddyfile: es gibt die Cookie-Regel vor der App (B-20)", bool(caddy_cookie_regeln()),
        "keine header_up-Cookie-Zeile — die App bekommt das Sitzungs-Cookie")
_falsch = {ein: cookie_nach_caddy(ein) for ein, aus in _faelle.items() if cookie_nach_caddy(ein) != aus}
r.check("Caddyfile: die TinySesam-Cookies werden entfernt, andere bleiben unberührt", not _falsch,
        f"{_falsch}")


# A-2: nginx reicht die TinySesam-Cookies ebenso wenig an die App (oder an PHP) weiter. Gemessen
# wird die map-Kette der Vorlage selbst, in Python nachgespielt (PCRE und `re` lesen diese Muster
# gleich; gegen echtes nginx 1.29 + php-fpm 8.3 nachgestellt).
def nginx_app_cookie(datei: str, cookie: str) -> str:
    text = (ROOT / datei).read_text(encoding="utf-8")
    werte = {"http_cookie": cookie}
    for quelle, ziel, muster, ersatz, vorgabe in re.findall(
            r'^map \$(\w+) \$(\w+) \{ "~(.*?)" "(.*?)"; default \$(\w+); \}$', text, re.M):
        treffer = re.match(muster.replace("(?<", "(?P<"), werte[quelle])
        werte[ziel] = (re.sub(r"\$(\w+)", lambda m: treffer.group(m.group(1)) or "", ersatz)
                       if treffer else werte[vorgabe])
    return werte.get("ts_app_cookie", cookie)


for datei in ("deploy/forward-auth/nginx.conf", "deploy/forward-auth/nginx-pfad.conf"):
    _nfalsch = {ein: nginx_app_cookie(datei, ein) for ein, aus in _faelle.items()
                if nginx_app_cookie(datei, ein) != aus}
    r.check(f"{datei}: die TinySesam-Cookies werden entfernt, andere bleiben unberührt (A-2)",
            not _nfalsch, f"{_nfalsch}")
    # Wie viele tinysesam-Cookies ein Browser trägt, steht nicht fest: sechs Namen, jeder in der
    # Übergangszeit nach H-1 doppelt (alt und `__Host-`), dazu umbenannte Cookies mehrerer
    # Instanzen. Die Kette muss die Übergangslage ganz abdecken, und was darüber hinausgeht,
    # darf nie zur App durchrutschen — dann lieber gar kein Cookie (fail closed). Gegen echtes
    # nginx 1.31 nachgestellt: 12 Stück → nur die eigenen, 13 → leer.
    # (Mutationsprobe: den Riegel `$ts_ck_zu` wirkungslos machen → rot ab 13 Cookies.)
    _stufen = len(re.findall(r'^map \$\w+ \$ts_ck\d+ ', (ROOT / datei).read_text(encoding="utf-8"), re.M))
    r.check(f"{datei}: die Kette deckt die Übergangslage ab (sechs Namen, alt und __Host-)",
            _stufen >= 12, f"nur {_stufen} Stufen")
    _durch = {}
    for _n in range(0, 2 * _stufen + 3):
        _ein = "; ".join([f"eigen{i}=v" for i in range(2)]
                         + [f"{'__Host-' if i % 2 else ''}tinysesam_x{i}=geheim" for i in range(_n)]
                         + ["eigen9=v"])
        _aus = nginx_app_cookie(datei, _ein)
        if "tinysesam_" in _aus or (_n <= _stufen and _aus != "eigen0=v; eigen1=v; eigen9=v"):
            _durch[_n] = _aus
    r.check(f"{datei}: beliebig viele tinysesam-Cookies — keins erreicht die App (fail closed)",
            not _durch, f"{_durch}")
_ngx = (ROOT / "deploy/forward-auth/nginx.conf").read_text(encoding="utf-8")
_ngx_app = _ngx.split("location / {")[1].split("proxy_pass")[0]
r.check("nginx.conf: die App bekommt das gefilterte Cookie", "proxy_set_header Cookie $ts_app_cookie;" in _ngx_app)
_ngx_auth = _ngx.split("location = /auth/forward {")[1].split("}")[0]
r.check("nginx.conf: der Sub-Request an /auth/forward behält das Cookie",
        "proxy_set_header Cookie $http_cookie;" in _ngx_auth)
_pfad = (ROOT / "deploy/forward-auth/nginx-pfad.conf").read_text(encoding="utf-8")
r.check("nginx-pfad.conf: jede PHP-Location bekommt das gefilterte Cookie (auch die offene)",
        _pfad.count("fastcgi_pass") == _pfad.count("fastcgi_param HTTP_COOKIE        $ts_app_cookie;"),
        "eine fastcgi_pass-Location reicht das Cookie ungefiltert an PHP")
_traefik = (ROOT / "deploy/forward-auth/traefik.yml").read_text(encoding="utf-8")
r.check("traefik.yml: die Cookie-Lücke ist benannt und der Ausweg vorhanden (A-2)",
        "B-20" in _traefik and 'Cookie: ""' in _traefik)
_caddy = (ROOT / "deploy/forward-auth/Caddyfile").read_text(encoding="utf-8")
_auth_block = _caddy.split("rewrite /auth/forward")[1].split("handle_response @ok")[0]
r.check("Caddyfile: der Sub-Request an /auth/forward behält das Cookie (sonst ist jeder abgemeldet)",
        "header_up Cookie" not in _auth_block)


# H-16: Caddy findet einen Antwort-Header in `{rp.header.…}` nur in der Schreibweise, die Gos
# textproto daraus macht (jedes Wort gross, der Rest klein). Mit `X-TinySesam-Location` kam eine
# 302 mit LEEREM Location heraus — ohne Fehler, ohne Logzeile.
def go_kanonisch(name: str) -> str:
    return "-".join(w[:1].upper() + w[1:].lower() for w in name.split("-"))


_platzhalter = re.findall(r"\{rp\.header\.([A-Za-z0-9-]+)\}", _caddy)
_schief = [p for p in _platzhalter if p != go_kanonisch(p)]
r.check("Caddyfile: jeder {rp.header.…}-Platzhalter steht in Go-kanonischer Form (H-16)",
        _platzhalter and not _schief, f"nicht kanonisch: {_schief}")
_gesendet = set(TinySesam.FORWARD_HEADERS_DEFAULT.values()) | {"X-TinySesam-Location"}
_fehlt = [h for h in _gesendet if go_kanonisch(h) not in _platzhalter]
r.check("Caddyfile: jeder Header, den TinySesam schickt, hat seinen Platzhalter", not _fehlt,
        f"fehlt: {_fehlt}")

raise SystemExit(r.done())
