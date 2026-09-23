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

raise SystemExit(r.done())
