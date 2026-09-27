"""Gespeicherte Werte englisch (Schema 12) — und die Sperre des Betreibers als öffentliche Methode.

PO-Entscheid 2026-09-27, „Alles übersetzen, auch DB-Werte“: Seit 0.22.0 heissen auch die Werte der
öffentlichen Oberfläche englisch, ohne Alias. Zwei davon stehen in der Datenbank:

- `api_key.kind` — `automat`/`mensch` → `automation`/`human`;
- der Payload offener Adresswechsel-Links (`magic_token`, `purpose='email_change'`) — `alt` → `old`.

Die Migration schreibt sie beim Start um (`Store._werte_englisch`, Stempel 12), der Code liest einen
alten Wert trotzdem richtig — eine ältere Fassung, die nach einem Rückschritt auf derselben Datei
lief, hat wieder alte hinterlassen — und schreibt nur neue. Der Rückweg auf 0.21.x steht als SQL in
`docs/BETRIEB.md`; diese Suite führt genau diesen Block aus, damit Doku und Wirkung nicht
auseinanderlaufen. Was 0.21.0 selbst mit einer Datei auf Stempel 12 tut, ist einmal mit dem echten
Code aus dem Tag gemessen (CHANGELOG 0.22.0) — hier nicht, weil der CI-Checkout keine Tags hat.

Dazu `auth.set_disabled(user_id, disabled)` (Stufe A): dieselbe Wirkung wie die Sperre im Panel,
das die Methode ruft — bis 0.21.x zeigte die Doku `auth.store.set_disabled(…, durch_betreiber=True)`,
das nur den Vermerk setzte.

Alle Prüfungen kommen ohne Extras aus.
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
    """(Ergebnis, Text) — was der Logger `tinysesam` dabei sagt, ab INFO."""
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
    """Wie eine ältere Fassung (oder der Betreiber mit `sqlite3`) direkt in die Datei schreiben."""
    con = sqlite3.connect(pfad)
    try:
        for s in sql:
            con.execute(*s) if isinstance(s, tuple) else con.executescript(s)
        con.commit()
    finally:
        con.close()


def _stand(pfad: str) -> tuple:
    """(Stempel, Key-Arten, Payloads der Adresswechsel-Links) — roh aus der Datei."""
    con = sqlite3.connect(pfad)
    try:
        return (con.execute("PRAGMA user_version").fetchone()[0],
                [z[0] for z in con.execute("SELECT kind FROM api_key ORDER BY id")],
                [json.loads(z[0]) for z in con.execute(
                    "SELECT payload FROM magic_token WHERE purpose='email_change' ORDER BY created_at, token_hash")])
    finally:
        con.close()


def _key_einfuegen(pfad: str, uid: int, kind: str) -> str:
    """Einen Key so anlegen, wie ihn 0.21.x ausstellt (`kind` wie dort) — gibt den Klartext zurück."""
    roh = "tsk_" + secrets.token_urlsafe(32)
    _roh(pfad, ("INSERT INTO api_key(user_id, name, prefix, key_hash, roles, kind, created_at, "
                "expires_at) VALUES (?,?,?,?,?,?,strftime('%s','now'),strftime('%s','now')+86400)",
                (uid, f"alt-{kind}", roh[:12] + "…", hashlib.sha256(roh.encode()).hexdigest(), "[]", kind)))
    return roh


def _link_einfuegen(pfad: str, uid: int, alt: str, neu: str) -> str:
    """Einen Adresswechsel-Link so anlegen, wie ihn 0.21.x ausstellt (Payload `{"alt": …}`)."""
    roh = secrets.token_urlsafe(32)
    _roh(pfad, ("INSERT INTO magic_token(token_hash, purpose, user_id, email, payload, created_at, "
                "expires_at) VALUES (?,?,?,?,?,strftime('%s','now'),strftime('%s','now')+3600)",
                (hashlib.sha256(roh.encode()).hexdigest(), "email_change", uid, neu,
                 json.dumps({"alt": alt}))))
    return roh


def _wirkung(a: TinySesam, mensch: str, automat: str) -> dict:
    """Was die beiden Keys an einer Route bewirken: der Menschen-Key allein und mit Sitzung, der
    Automaten-Key allein."""
    app = _app(a)
    ohne = TestClient(app)
    mit = TestClient(app)
    mit.post("/auth/login", data={"username": "anna", "password": PW}, follow_redirects=False)
    a_allein = ohne.get("/wer", headers={"X-API-Key": automat})
    return {"mensch_allein": ohne.get("/wer", headers={"X-API-Key": mensch}).status_code,
            "mensch_mit_sitzung": mit.get("/wer", headers={"X-API-Key": mensch}).status_code,
            "automat_allein": a_allein.status_code,
            "automat_kind": a_allein.json().get("kind") if a_allein.status_code == 200 else None}


# ── (a) Eine Datei aus 0.21.x: der Start migriert, die Keys wirken wie vorher ──────────────────────
# (Mutationsproben: den Aufruf von `_werte_englisch` in `_migrate` streichen → (a) rot, die Arten
# bleiben alt; `KEY_ARTEN_ALT` leeren → (a)/(b) rot, `mensch` gilt als Automaten-Key und der Key
# wirkt ohne Sitzung — genau das, was 0.21.x mit einem `human`-Key tut.)
pfad_a = os.path.join(tempfile.mkdtemp(), "a.db")
post_a: list = []
a = _aufbau(pfad_a, post_a)
anna = a.create_user("anna", password=PW, email="anna@example.com")
mensch_a = a.create_api_key(anna, name="cli", kind="human")["key"]
automat_a = a.create_api_key(anna, name="ci")["key"]
a.request_email_change(anna, "anna.neu@example.com", BASIS)()
link_a = _link(post_a)
a.store.db.close()
# So lag die Datei unter 0.21.x: alte Werte, Stempel 11.
_roh(pfad_a, "UPDATE api_key SET kind='mensch' WHERE kind='human';"
             "UPDATE api_key SET kind='automat' WHERE kind='automation';"
             "UPDATE magic_token SET payload=json_object('alt', json_extract(payload, '$.old')) "
             "WHERE purpose='email_change';"
             "PRAGMA user_version = 11;")
vorher_a = _stand(pfad_a)
a, log_a = _mitschreiben(lambda: _aufbau(pfad_a, post_a))
nachher_a = _stand(pfad_a)
r.check("Vorbedingung: die Datei trägt die Werte von 0.21.x und den Stempel 11",
        vorher_a == (11, ["mensch", "automat"], [{"alt": "anna@example.com"}]), str(vorher_a))
r.check("(a) der Start migriert: Stempel 12, `automation`/`human`, Payload `old` — und sagt es im Log",
        nachher_a == (12, ["human", "automation"], [{"old": "anna@example.com"}])
        and "3 gespeicherte Werte auf die englischen Namen umgeschrieben" in log_a,
        f"{nachher_a} {log_a[-300:]!r}")
w_a = _wirkung(a, mensch_a, automat_a)
r.check("(a) … die Keys wirken wie vorher: der Menschen-Key nur mit Sitzung, der Automaten-Key allein",
        w_a == {"mensch_allein": 401, "mensch_mit_sitzung": 200, "automat_allein": 200,
                "automat_kind": "automation"}, str(w_a))
r.check("(a) … `api_key_kind`, `list_api_keys` und der offene Link nennen die englischen Werte",
        a.api_key_kind(mensch_a) == "human" and a.api_key_kind(automat_a) == "automation"
        and sorted(k["kind"] for k in a.list_api_keys(anna)) == ["automation", "human"]
        and a.peek_magic(link_a, purpose="email_change")["payload"] == {"old": "anna@example.com"})
a.store.db.close()
a, log_a2 = _mitschreiben(lambda: _aufbau(pfad_a, post_a))
r.check("(a) zweiter Start: nichts mehr umzuschreiben (idempotent), dieselbe Datei",
        _stand(pfad_a) == nachher_a and "umgeschrieben" not in log_a2, log_a2[-300:])
r.check("(a) … und der Link aus 0.21.x löst sich ein wie jeder andere",
        a.confirm_email_change(link_a) == "ok" and a.get_user(anna)["email"] == "anna.neu@example.com")
a.store.db.close()

# ── (a') Audit- und Log-Zeilen bleiben, wie sie waren ────────────────────────────────────────────
# Filter der Betreiber hängen an ihnen (PO-Entscheid 2026-09-27): Die Art eines Keys steht dort
# weiter als `art=automat`/`art=mensch`, die Zeile im Sicherheits-Log nennt `'mensch'`.
# (Mutationsprobe: `_key_art_audit` gibt den englischen Namen zurück → (a') rot.)
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
r.check("(a') Audit: `apikey_create`/`apikey_use` nennen die Art weiter mit `art=automat|mensch`",
        {"apikey_create:mensch", "apikey_create:automat", "apikey_use:automat"} <= _details, str(_details))
r.check("(a') Sicherheits-Log: der Menschen-Key ohne Sitzung heisst dort weiter `'mensch'`",
        "API-Key der Art 'mensch' ohne passende Sitzung" in _sec.getvalue(), _sec.getvalue()[-300:])
g.store.db.close()

# ── (b) Rückschritt: 0.21.x hat auf der Datei (Stempel 12) wieder alte Werte geschrieben ──────────
# Eine ältere Fassung senkt den Stempel nicht. Gelesen wird ein alter Wert trotzdem richtig, auch
# ohne Neustart (ein zweiter Prozess, der noch 0.21.x fährt); der nächste Start schreibt die Keys um.
# Den Payload eines Links nur beim Sprung auf 12 (die Suche ginge sonst bei jedem Start durch alle
# Einmal-Token, tests/test_bestandsdaten.py „Aufwand") — `peek_magic` bildet ihn beim Lesen ab.
# (Mutationsprobe: in `TinySesam._key_kind` die Abbildung weglassen → (b) rot: der `mensch`-Key
# wirkt ohne Sitzung.)
pfad_b = os.path.join(tempfile.mkdtemp(), "b.db")
b = _aufbau(pfad_b)
anna_b = b.create_user("anna", password=PW, email="anna@example.com")
neu_b = b.create_api_key(anna_b, name="neu", kind="human")["key"]
mensch_b = _key_einfuegen(pfad_b, anna_b, "mensch")
automat_b = _key_einfuegen(pfad_b, anna_b, "automat")
link_b = _link_einfuegen(pfad_b, anna_b, "anna@example.com", "anna.b@example.com")
r.check("Vorbedingung: gemischte Werte bei Stempel 12",
        _stand(pfad_b)[:2] == (12, ["human", "mensch", "automat"]), str(_stand(pfad_b)))
w_b = _wirkung(b, mensch_b, automat_b)
# `list_api_keys` sortiert nach `created_at` (Sekunden) absteigend. Der Key aus der Bibliothek und
# die beiden roh eingefügten entstehen nicht in derselben Sekunde, wenn der Rechner ausgelastet ist
# (parallele Suiten) — dann stand der jüngste vorn, und die Prüfung der Reihenfolge wurde rot,
# obwohl jede Art stimmte. Geprüft wird deshalb je Key über seinen Namen.
r.check("(b) gemischt, ohne Neustart: `mensch` gilt als `human` (nur mit Sitzung), `automat` als "
        "`automation`",
        w_b == {"mensch_allein": 401, "mensch_mit_sitzung": 200, "automat_allein": 200,
                "automat_kind": "automation"}
        and [b.api_key_kind(k) for k in (neu_b, mensch_b, automat_b)] == ["human", "human", "automation"]
        and {k["name"]: k["kind"] for k in b.list_api_keys(anna_b)}
        == {"neu": "human", "alt-mensch": "human", "alt-automat": "automation"},
        f"{w_b} {[(k['name'], k['kind']) for k in b.list_api_keys(anna_b)]}")
r.check("(b) … der Link aus 0.21.x zeigt `old`, nicht `alt`",
        b.peek_magic(link_b, purpose="email_change")["payload"] == {"old": "anna@example.com"})
b.store.db.close()
b, log_b = _mitschreiben(lambda: _aufbau(pfad_b))
r.check("(b) der nächste Start schreibt die Keys um (bei jedem Start), den Link nicht (Stempel schon 12)",
        _stand(pfad_b) == (12, ["human", "human", "automation"], [{"alt": "anna@example.com"}])
        and "2 gespeicherte Werte" in log_b, f"{_stand(pfad_b)} {log_b[-200:]!r}")
r.check("(b) … und er gilt weiter, eingelöst mit `old` im Ergebnis",
        b.redeem_magic(link_b, purpose="email_change")["payload"] == {"old": "anna@example.com"})
b.store.db.close()

# ── (c) Der Rückweg aus docs/BETRIEB.md: genau der Block, der dort steht ──────────────────────────
# (Mutationsprobe: im SQL-Block der Doku die Zeile für `mensch` streichen → (c) rot.)
_doku = (ROOT / "docs" / "BETRIEB.md").read_text(encoding="utf-8")
_abschnitt = _doku.split("## Rückschritt auf 0.21.x", 1)[-1] if "## Rückschritt auf 0.21.x" in _doku else ""
_sql = re.search(r"```sql\n(.*?)```", _abschnitt, re.S)
r.check("docs/BETRIEB.md hat den Abschnitt „Rückschritt auf 0.21.x“ mit einem SQL-Block",
        bool(_sql), "Abschnitt oder ```sql-Block fehlt")
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
    r.check("(c) das SQL aus der Doku stellt die Werte von 0.21.x her und senkt den Stempel auf 11",
            _stand(pfad_c) == (11, ["mensch", "automat"], [{"alt": "anna@example.com"}]), str(_stand(pfad_c)))
    c = _aufbau(pfad_c, post_c)
    r.check("(c) … und ein Start von 0.22.0 danach migriert wieder (Hin und Rück ohne Verlust)",
            _stand(pfad_c) == (12, ["human", "automation"], [{"old": "anna@example.com"}]), str(_stand(pfad_c)))
    c.store.db.close()

# ── (d) Nur lesbar ────────────────────────────────────────────────────────────────────────────────
# Alte Werte bei Stempel 12 (Rückschritt) auf einer Datei ohne Schreibrecht: Der Start darf nicht
# scheitern, der bisher ging — gelesen wird ohnehin richtig. Ein Upgrade (Stempel 11) dagegen braucht
# Schreibrecht wie jede Migration. Nur lesbar macht der Test den Schritt selbst, echt über
# `PRAGMA query_only` (die übrigen Schritte des Starts schreiben nichts, was hier zählt).
# (Mutationsprobe: das `try` um `_werte_englisch` streichen → (d) rot, der Start scheitert.)
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
    except Exception as fehler:          # der Start selbst scheitert
        log_d, start_d = "", f"{type(fehler).__name__}: {fehler}"
    r.check("(d) nur lesbar, Stempel 12, alte Werte: der Start gelingt, sagt es, liest `mensch` als `human`",
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
    r.check("(d) … ein Upgrade (Stempel 11) ohne Schreibrecht bricht ab, wie jede Migration",
            upgrade_d.startswith("OperationalError"), upgrade_d)
finally:
    Store._werte_englisch = _original

# ── (e) Die alten Namen sind Eingabefehler, deren Text den neuen nennt — kein Alias ────────────────
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
r.check("(e) `create_api_key(kind='automat'|'mensch')` → ConfigError, der den neuen Namen nennt",
        all(f"heisst seit 0.22.0 {neu!r}" in _texte[alt] for alt, neu in
            (("automat", "automation"), ("mensch", "human"))), str(_texte))
_ce = TestClient(_app(e))
_ce.post("/auth/login", data={"username": "bert", "password": PW}, follow_redirects=False)
_antwort = _ce.post("/auth/apikeys", json={"name": "x", "kind": "mensch"})
_standard = _ce.post("/auth/apikeys", json={"name": "y"})
r.check("(e) … über `POST /auth/apikeys` 400 mit demselben Hinweis; ohne `kind` ein `automation`-Key",
        _antwort.status_code == 400 and "'human'" in _antwort.json()["detail"]
        and _standard.status_code == 200 and _standard.json()["kind"] == "automation"
        and "dropped_roles" in _standard.json(), f"{_antwort.text[:200]} {_standard.text[:200]}")
e.store.db.close()

# ── (f) auth.set_disabled: die Sperre des Betreibers mit der ganzen Wirkung ────────────────────────
# (Mutationsproben, je einzeln: in `set_disabled` das Beenden der Sitzungen streichen → rot; den
# Widerruf der Keys → rot; `revoke_user_magic_tokens` → rot; `durch_betreiber=True` weglassen → rot
# (der Bestätigungslink hebt die Sperre auf); die Audit-Zeile → rot.)
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
r.check("Vorbedingung: bert ist angemeldet, sein Key wirkt, sein Anmelde-Link ist offen",
        cb.get("/wer").status_code == 200 and f.verify_api_key(key_f)[0] is not None
        and f.peek_magic(link_f) is not None)
_vor = f.store._one("SELECT MAX(id) AS m FROM audit")["m"]
r.check("(f) `set_disabled(uid, True)` ohne Anfrage → True", f.set_disabled(bert_f, True) is True)
_zeile = f.store._one("SELECT event, username, ip, detail FROM audit WHERE id > ? AND event='user_disable'",
                      (_vor,))
r.check("(f) … mit Betreiber-Vermerk, Sitzung beendet, Key widerrufen, Link verworfen",
        f.get_user(bert_f)["disabled"] == Store.GESPERRT_BETREIBER and cb.get("/wer").status_code == 401
        and f.verify_api_key(key_f) == (None, None) and f.peek_magic(link_f) is None
        and [k["revoked"] for k in f.list_api_keys(bert_f)] == [1])
r.check("(f) … Audit `user_disable` unter dem betroffenen Konto, Ereignis `api_keys_revoked` mit `reason`",
        _zeile is not None and dict(_zeile) == {"event": "user_disable", "username": "bert", "ip": None,
                                                "detail": f"uid={bert_f} api_keys_revoked=1"}
        and ("api_keys_revoked", {"count": 1, "reason": "account_disabled"}) in ereignisse_f,
        f"{_zeile and dict(_zeile)} {ereignisse_f}")
_verify = f.create_magic_token("verify_email", user_id=bert_f, email="bert@example.com")
_v = TestClient(app_f).post(f"/auth/verify/{_verify}", follow_redirects=False)
r.check("(f) … ein Bestätigungslink, der erst danach entsteht, hebt die Sperre nicht auf (H-18)",
        _v.status_code == 403 and f.get_user(bert_f)["disabled"] == Store.GESPERRT_BETREIBER, str(_v.status_code))
r.check("(f) `set_disabled(uid, False)` entsperrt; der widerrufene Key bleibt widerrufen, die beendete "
        "Sitzung beendet (sonst lebte sie mit dem Entsperren wieder auf)",
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
r.check("(f) ein Owner lässt sich nicht sperren: StateError, und nichts ist geschehen",
        _owner == "StateError" and f.get_user(chefin)["disabled"] == 0
        and f.store._one("SELECT 1 FROM audit WHERE id > ?", (_vor,)) is None, _owner)
r.check("(f) ein unbekanntes Konto: False, keine Audit-Zeile",
        f.set_disabled(9999, True) is False
        and f.store._one("SELECT 1 FROM audit WHERE id > ?", (_vor,)) is None)

# Das Panel ruft genau diese Methode — und schreibt dieselbe Zeile wie bis 0.21.x: der Admin als
# Konto, seine IP, `uid=… api_keys_revoked=…`.
ca = TestClient(app_f)
ca.post("/auth/login", data={"username": "chefin", "password": PW}, follow_redirects=False)
f.create_api_key(bert_f, name="zwei")
_vor = f.store._one("SELECT MAX(id) AS m FROM audit")["m"]
_p = ca.post(f"/auth/admin/api/users/{bert_f}/disable", json={"disabled": True})
_zeile = f.store._one("SELECT event, username, ip, detail FROM audit WHERE id > ? AND event='user_disable'",
                      (_vor,))
r.check("(f) Panel: 200, dieselbe Wirkung, Audit unter dem Admin mit seiner IP (wie bis 0.21.x)",
        _p.status_code == 200 and f.get_user(bert_f)["disabled"] == Store.GESPERRT_BETREIBER
        and _zeile is not None and dict(_zeile) == {"event": "user_disable", "username": "chefin",
                                                    "ip": "testclient",
                                                    "detail": f"uid={bert_f} api_keys_revoked=1"},
        f"{_p.status_code} {_zeile and dict(_zeile)}")
r.check("(f) Panel: ein unbekanntes Konto → 404 statt 200 (bis 0.21.x „ok“ und eine Audit-Zeile)",
        ca.post("/auth/admin/api/users/9999/disable", json={"disabled": True}).status_code == 404)
f.store.db.close()

# Eine Quelle: Die Panel-Route ruft `auth.set_disabled` und keinen der Schritte selbst.
_admin = ast.parse((ROOT / "tinysesam" / "admin.py").read_text(encoding="utf-8"))
_route = next(k for k in ast.walk(_admin) if isinstance(k, ast.AsyncFunctionDef) and k.name == "user_disable")
_rufe = {ast.unparse(k.func) for k in ast.walk(_route) if isinstance(k, ast.Call)}
_ueberall = {ast.unparse(k.func) for k in ast.walk(_admin) if isinstance(k, ast.Call)}
r.check("(f) eine Quelle: `user_disable` ruft `auth.set_disabled`, keinen Schritt selbst; admin.py ruft "
        "`store.set_disabled` nirgends",
        "auth.set_disabled" in _rufe
        and not _rufe & {"auth.store.set_disabled", "auth.store.delete_user_sessions", "auth._keys_widerrufen",
                         "auth.store.revoke_user_magic_tokens", "protokoll"}
        and "auth.store.set_disabled" not in _ueberall, str(sorted(_rufe)))

raise SystemExit(r.done())
