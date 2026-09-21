"""Nachgestellte Angriffe aus der Reifeprüfung vom 2026-09-21.

Jede Prüfung hier hält einen Angriff fest, der einmal funktioniert hat. Sie sind bewusst nach dem
ANGRIFF benannt, nicht nach der Funktion — wer eine davon rot sieht, soll sofort wissen, was
wieder möglich ist.

Alles läuft auf Vorgabewerten. Ein Fund, der nur unter einer Konfiguration auftritt, die niemand
wählt, wäre keiner gewesen.
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Sicherheit — nachgestellte Angriffe")


def _app(**cfg):
    """Eine Instanz auf Vorgabewerten, nur mit eigenem Datenbankpfad."""
    tmp = tempfile.mkdtemp()
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False)
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# ── Rollen-Eskalation über selbst ausgestellte API-Keys ────────────────────────
# Angriff: Ein angemeldeter Nutzer ohne jede Rolle ruft POST /auth/apikeys mit
# {"roles": ["buchhaltung"]} auf und bekommt einen Key, der genau diese Rolle trägt.
# Der Scope überschrieb die Kontorollen, statt sie zu schneiden.
auth, app = _app()
auth.create_user("mitarbeiter", password="Geheim12345!")
nutzer = auth.store.get_user_by_name("mitarbeiter")


@app.get("/nur-buchhaltung")
def _geschuetzt(u=Depends(auth.require_role("buchhaltung"))):
    return {"gesehen_von": u["username"]}


r.check("Ausgangslage: das Konto hat keine Rollen", auth.user_roles(nutzer) == [])

key = auth.create_api_key(nutzer["id"], name="probe", roles=["buchhaltung"])
r.check("ein Key kann keine Rolle tragen, die sein Besitzer nicht hat",
        key.get("roles") == [],
        f"der Key trägt {key.get('roles')}")
r.check("der Versuch wird nicht stillschweigend verworfen, sondern vermerkt",
        key.get("verworfene_rollen") == ["buchhaltung"])

with TestClient(app) as c:
    antwort = c.get("/nur-buchhaltung", headers={"Authorization": f"Bearer {key['key']}"})
r.check("und der Key öffnet die geschützte Route NICHT", antwort.status_code == 403,
        f"HTTP {antwort.status_code} — die Rollen-Eskalation ist zurück")

# Gegenprobe: Wer die Rolle wirklich hat, bekommt sie auch im Key — sonst wäre der Fix
# eine Funktionsbremse statt einer Absicherung.
auth.set_roles(nutzer["id"], ["buchhaltung"]) if hasattr(auth, "set_roles") else None
nutzer2 = auth.store.get_user_by_name("mitarbeiter")
if auth.user_roles(nutzer2) == ["buchhaltung"]:
    key2 = auth.create_api_key(nutzer2["id"], name="echt", roles=["buchhaltung"])
    r.check("wer die Rolle hat, behält sie im Key", key2.get("roles") == ["buchhaltung"])
    with TestClient(app) as c:
        a2 = c.get("/nur-buchhaltung", headers={"Authorization": f"Bearer {key2['key']}"})
    r.check("und kommt damit durch", a2.status_code == 200, f"HTTP {a2.status_code}")

# ── OIDC: der Flow muss an den Browser gebunden sein ──────────────────────────
# Angriff: Der Angreifer startet den Flow bei sich, meldet sich beim IdP als er selbst an und
# lockt das Opfer auf die Callback-URL. Das Opfer landet still im Konto des Angreifers. Ein
# gewöhnlicher Top-Level-GET genügt — SameSite hilft nicht, weil gar kein Cookie gebraucht wird.
# Geprüft wird die Bindung selbst; ein echter IdP ist dafür nicht nötig.
auth_o, app_o = _app(oidc_enabled=True, oidc_issuer="https://idp.example.invalid",
                     oidc_client_id="probe", oidc_client_secret="geheim",
                     base_url="http://testserver")
# Metadaten vorbefüllen, damit kein Netz nötig ist: Geprüft wird die Browser-Bindung,
# nicht die Discovery. `meta()` holt sonst beim ersten Aufruf die well-known-URL.
auth_o.oidc._meta = {
    "issuer": "https://idp.example.invalid",
    "authorization_endpoint": "https://idp.example.invalid/authorize",
    "token_endpoint": "https://idp.example.invalid/token",
    "userinfo_endpoint": "https://idp.example.invalid/userinfo",
    "jwks_uri": "https://idp.example.invalid/jwks",
}

with TestClient(app_o) as c:
    start = c.get("/auth/oidc/start", follow_redirects=False)
r.check("der Start setzt ein Flow-Cookie", "tinysesam_oidc_flow" in start.headers.get("set-cookie", ""),
        f"keins gesetzt: {start.headers.get('set-cookie', '—')[:60]}")
r.check("und zwar httponly (kein Zugriff aus JavaScript)",
        "httponly" in start.headers.get("set-cookie", "").lower())

# Den state aus der Weiterleitung lesen — genau das, was ein Angreifer kann.
from urllib.parse import parse_qs, urlparse  # noqa: E402
state = parse_qs(urlparse(start.headers["location"]).query).get("state", [""])[0]
r.check("der state steht wie erwartet in der Weiterleitung", bool(state))

# Callback aus einem FREMDEN Browser (eigene Cookie-Sammlung, ohne das Flow-Cookie).
with TestClient(app_o) as fremd:
    antwort = fremd.get(f"/auth/oidc/callback?code=egal&state={state}", follow_redirects=False)
r.check("ein Callback ohne passendes Flow-Cookie wird abgewiesen",
        antwort.status_code == 400,
        f"HTTP {antwort.status_code} — die Konto-Unterschiebung ist zurück")

# ── Schreibende Routen ohne CSRF-Prüfung ──────────────────────────────────────
# Angriff: Ein <form method=POST> auf einer fremden Seite, ohne Body, ohne Preflight.
# `POST /auth/totp/disable` löschte damit TOTP UND alle Recovery-Codes — ohne Rückfrage,
# ohne frische Faktor-Bestätigung und ohne Audit-Eintrag.
auth_c, app_c = _app(pin_enabled=True)
auth_c.create_user("opfer", password="Geheim12345!")
opfer = auth_c.store.get_user_by_name("opfer")
auth_c.totp_enable(opfer["id"], auth_c.totp_new_secret()) if hasattr(auth_c, "totp_new_secret") else None

OHNE_CSRF = ("/auth/totp/disable", "/auth/totp/recovery", "/auth/pin/disable")
with TestClient(app_c) as c:
    c.post("/auth/login", data={"username": "opfer", "password": "Geheim12345!"},
           follow_redirects=False)
    for pfad in OHNE_CSRF:
        antwort = c.post(pfad)          # kein X-CSRF-Token, kein Body — wie ein fremdes Formular
        r.check(f"{pfad} verlangt einen CSRF-Token", antwort.status_code == 403,
                f"HTTP {antwort.status_code} — ohne Token durchgekommen")

# Das Abschalten des zweiten Faktors muss eine Spur hinterlassen. Ohne Eintrag ist hinterher
# nicht nachvollziehbar, dass jemandem der zweite Faktor abhandenkam.
auth_c.totp_disable(opfer["id"])
ereignisse = [e["event"] for e in auth_c.store.recent_audit(limit=20)]
r.check("das Abschalten von TOTP wird protokolliert", "totp_disable" in ereignisse,
        f"kein Eintrag — gefunden: {ereignisse[:6]}")
auth_c.disable_pin(opfer["id"])
r.check("das Abschalten der PIN ebenso",
        "pin_disable" in [e["event"] for e in auth_c.store.recent_audit(limit=20)])

# ── Brute-Force-Sperre per erfolgreichem Erstfaktor zurücksetzbar ─────────────
# Angriff: Wer das Passwort kennt (Leak, Wiederverwendung, Phishing), meldet sich vor jedem
# TOTP-Rateversuch einmal korrekt an. Der Erfolg löschte ALLE Fehlversuche des Kontos — auch die
# der TOTP-Versuche. Die Sperre griff für den zweiten Faktor damit nie.
auth_b, _app_b = _app()
auth_b.create_user("ziel", password="Geheim12345!")

# Fünf Fehlversuche beim zweiten Faktor …
for _ in range(5):
    auth_b.record_login("ziel", "203.0.113.9", success=False, method="totp")
offen_vorher = len(auth_b.store.recent_fails("ziel")) if hasattr(auth_b.store, "recent_fails") else None

# … dann ein ERFOLGREICHER Passwort-Login.
auth_b.record_login("ziel", "203.0.113.9", success=True, method="password")

# Die TOTP-Fehlversuche müssen stehen bleiben.
rest = auth_b.store._all(
    "SELECT method FROM login_attempt WHERE username=? COLLATE NOCASE AND success=0", ("ziel",))
totp_übrig = [z["method"] for z in rest].count("totp")
r.check("ein Passwort-Erfolg räumt die TOTP-Fehlversuche NICHT weg", totp_übrig == 5,
        f"{totp_übrig} von 5 übrig — der zweite Faktor ist wieder ratbar")

# Gegenprobe: Passwort-Fehlversuche räumt er sehr wohl weg, sonst wäre der Fix eine Bremse.
for _ in range(3):
    auth_b.record_login("ziel2", "203.0.113.9", success=False, method="password")
auth_b.record_login("ziel2", "203.0.113.9", success=True, method="password")
pw_übrig = [z["method"] for z in auth_b.store._all(
    "SELECT method FROM login_attempt WHERE username=? COLLATE NOCASE AND success=0",
    ("ziel2",))].count("password")
r.check("eigene Fehlversuche räumt ein Erfolg weiterhin weg", pw_übrig == 0,
        f"{pw_übrig} übrig — der Fix bremst mehr als nötig")


# ── Erst-Admin kapern: Allowlist-Name + offene Selbst-Registrierung ────────────
# `admin_identifiers` verbürgt nur, WELCHER Name Admin wird — nicht, wer ihn bekommt. Mit
# `allow_signup=True` registriert sich der Erste, der die Adresse errät, genau darunter und ist
# beim ersten Login Admin. Der Konstruktor lässt diese Kombination nicht mehr zu.
def _baut(**cfg):
    """(gebaut?, Fehlertext) — ohne die Prüfung zum Fehlschlag der Suite zu machen."""
    tmp = tempfile.mkdtemp()
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False)
    grund.update(cfg)
    try:
        TinySesam(TinySesamConfig(**grund))
        return True, ""
    except ValueError as e:
        return False, str(e)


gebaut, text = _baut(admin_identifiers=["chef"], allow_signup=True)
r.check("Allowlist-BENUTZERNAME + allow_signup wird abgewiesen", not gebaut,
        "die Instanz baut — wer sich als 'chef' registriert, wird Erst-Admin")
r.check("die Abweisung nennt den betroffenen Eintrag", "chef" in text,
        f"Meldung nennt ihn nicht: {text[:80]!r}")

# Auch eine E-Mail reicht nicht, solange sie niemand bestätigt: bei der Registrierung ist sie
# ein frei eintippbares Feld.
gebaut, _ = _baut(admin_identifiers=["chef@example.com"], allow_signup=True,
                  signup_require_email=True, signup_verify_email=False)
r.check("Allowlist-E-MAIL ohne Bestätigungspflicht wird abgewiesen", not gebaut,
        "die Instanz baut — die Adresse ist unbestätigt und damit frei wählbar")

# Gegenproben — der Wächter darf die tragfähigen Aufbauten nicht mitnehmen.
gebaut, text = _baut(admin_identifiers=["chef@example.com"], allow_signup=True,
                     signup_require_email=True, signup_verify_email=True)
r.check("bestätigte E-Mail + offene Registrierung bleibt erlaubt", gebaut,
        f"zu streng, der belegte Weg ist zu: {text[:120]}")

gebaut, text = _baut(admin_identifiers=["chef"], allow_signup=False)
r.check("Allowlist ohne Selbst-Registrierung bleibt erlaubt", gebaut,
        f"zu streng, der Normalfall ist zu: {text[:120]}")


# ── Untergeschobene SAML-Assertion (Login-CSRF / unsolicited Response) ─────────
# Die ACS nahm jede signierte Assertion an. `InResponseTo` band sie an nichts: python3-saml
# prüft das Feld nur, wenn es dasteht — eine Antwort ganz ohne es ging durch. Ein Angreifer mit
# einer gültigen Assertion für SEIN Konto konnte sie so in den Browser des Opfers POSTen.
from tinysesam.saml_ import SAMLClient  # noqa: E402


class _Antwort:
    """Ein IdP, dessen Assertion Signatur und Conditions besteht — nur der Bezug wechselt."""

    def __init__(self, in_response_to):
        self.irt = in_response_to
        self.gesehen = "__nie_gesetzt__"

    def process_response(self, request_id=None):
        self.gesehen = request_id

    def get_errors(self):
        return []

    def get_last_error_reason(self):
        return ""

    def is_authenticated(self):
        return True

    def get_last_response_in_response_to(self):
        return self.irt

    def get_nameid(self):
        return "angreifer@example.com"

    def get_attributes(self):
        return {}


def _saml_lauf(in_response_to, request_id):
    auth_s, _ = _app()
    client = SAMLClient(auth_s.cfg)
    idp = _Antwort(in_response_to)
    client._auth = lambda req, base: idp
    return client.process({}, "https://app.example.com", request_id=request_id), idp


daten, _ = _saml_lauf(None, "_meine-id")
r.check("Assertion OHNE InResponseTo wird abgelehnt", daten is None,
        "angenommen — jede signierte Assertion loggt jeden ein (Login-CSRF)")

daten, _ = _saml_lauf("_fremde-id", "_meine-id")
r.check("Assertion mit FREMDEM InResponseTo wird abgelehnt", daten is None,
        "angenommen — die Antwort gehört zu einem anderen Anmeldeversuch")

daten, _ = _saml_lauf("_meine-id", "")
r.check("ohne angeforderten Request bleibt die ACS zu", daten is None,
        "angenommen — ohne eigene Anforderung darf nichts eingelöst werden")

# Gegenprobe: der reguläre Weg muss durchkommen, sonst ist der Fix eine Mauer.
daten, idp = _saml_lauf("_meine-id", "_meine-id")
r.check("die angeforderte Assertion kommt weiterhin durch", daten is not None,
        "der reguläre SAML-Login ist zu")
r.check("die Request-ID wird auch an die Bibliothek durchgereicht", idp.gesehen == "_meine-id",
        f"process_response sah {idp.gesehen!r} — die Prüfung liefe nur in TinySesam, nicht in python3-saml")


# Und der Anker muss VERDRAHTET sein: Der Router legt die Request-ID ab und reicht sie wieder an.
class _FakeSAML:
    def __init__(self):
        self.gesehene_request_id = "__nie_gesetzt__"

    def login_url(self, req, base, return_to="/"):
        return ("https://idp.example.com/sso?SAMLRequest=abc", "_authnreq-4711")

    def process(self, req, base, request_id=""):
        self.gesehene_request_id = request_id
        return None          # der Rest des Flows interessiert hier nicht

    def metadata(self, base):
        return "<md:EntityDescriptor/>"


auth_r, app_r = _app(saml_enabled=True, saml_idp_sso_url="https://idp.example.com/sso",
                     saml_idp_x509cert="MIIB", base_url="https://app.example.com")
auth_r.saml = _FakeSAML()
app_r = FastAPI()
app_r.include_router(auth_r.router())
cr = TestClient(app_r)

antwort = cr.get("/auth/saml/login?next=/", follow_redirects=False)
keks = antwort.cookies.get("tinysesam_saml_flow")
r.check("der Login legt die Request-ID in ein Flow-Cookie", keks == "_authnreq-4711",
        f"Cookie ist {keks!r} — ohne Ablage gibt es bei der ACS nichts zu vergleichen")
r.check("das Flow-Cookie ist httponly", "httponly" in antwort.headers.get("set-cookie", "").lower(),
        "per JavaScript lesbar")

cr.post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
r.check("die ACS reicht die abgelegte Request-ID an die Prüfung weiter",
        auth_r.saml.gesehene_request_id == "_authnreq-4711",
        f"sie sah {auth_r.saml.gesehene_request_id!r} — der Anker hängt an keinem Draht")


# ── Sitzungen übernehmen: aus der Datei oder aus dem Admin-Panel ───────────────
# Sitzungs-Token lagen im Klartext in der Datenbank, und `GET /admin/api/sessions` gab sie
# obendrein an den Browser. Beides zusammen heisst: Wer die Datei liest (sie lag bei 0644) oder
# eine Panel-Antwort sieht, meldet sich als beliebiger Nutzer an. Gespeichert wird jetzt nur der
# sha256; das Panel bekommt dieses Handle, mit dem man beenden, aber nicht anmelden kann.
auth_t, app_t = _app()
auth_t.create_user("opfer", password="geheim12345")
opfer_id = auth_t.store.get_user_by_name("opfer")["id"]
# `create_session` gibt zurück, was ins Cookie geht — genau der Wert, um den es geht.
cookie_wert = auth_t.store.create_session(opfer_id, 3600, True, "password")

gespeichert = [z["token_hash"] for z in auth_t.store._all("SELECT token_hash FROM session")]
# sha256 hier selbst rechnen: ein Test, der `store.session_hash()` fragt, misst gegen dieselbe
# Funktion, die er prüft — und bliebe grün, wenn die zur Identität mutiert.
erwartet = hashlib.sha256(cookie_wert.encode()).hexdigest()
r.check("in der Datenbank steht kein Klartext-Token", gespeichert == [erwartet],
        f"gespeichert: {gespeichert[:1]} — erwartet war der sha256 des Cookies")
r.check("das Cookie ist NICHT der gespeicherte Wert",
        bool(cookie_wert) and cookie_wert not in gespeichert,
        "wer die Datei liest, hat das Anmelde-Token")

# Das Handle darf sich nicht als Cookie einsetzen lassen.
handle = gespeichert[0]
r.check("das Handle taugt nicht als Sitzungs-Cookie",
        auth_t.store.get_session(handle) is None,
        "der gespeicherte Wert meldet an — dann ist das Hashen wirkungslos")
r.check("das echte Cookie meldet weiterhin an",
        auth_t.store.get_session(cookie_wert) is not None,
        "die Sitzung ist gar nicht auffindbar — dann misst der Test nichts")

# Und das Panel gibt genau dieses Handle heraus, nicht das Token.
panel = [z["token_hash"] for z in auth_t.store.list_sessions()]
r.check("das Admin-Panel bekommt nur Handles zu sehen", panel == [handle],
        f"list_sessions liefert {panel[:1]}")

# ... aber sehr wohl zum Beenden, sonst wäre das Panel kaputt.
auth_t.store.delete_session_by_handle(handle)
r.check("das Handle beendet die Sitzung weiterhin",
        auth_t.store.get_session(cookie_wert) is None,
        "das Panel kann keine Sitzung mehr beenden")

# Und ein Klartext-Token an einer Handle-Stelle ist ein Fehler, kein stiller No-Op:
# ein UPDATE, das keine Zeile trifft, liesse einen bestätigten Faktor lautlos verschwinden.
try:
    auth_t.store.set_session_mfa("nicht-ein-hash", True)
    lautlos = True
except ValueError:
    lautlos = False
r.check("ein Klartext-Token an einer Handle-Stelle fliegt auf", not lautlos,
        "läuft ins Leere — die Sitzung behielte still ihren alten Stand")


# Die Umstellung darf niemanden auswerfen: der Hash ist aus dem Klartext berechenbar, also lassen
# sich bestehende Zeilen migrieren. Eine Datenbank im alten Format nachbauen und öffnen.
import sqlite3 as _sq  # noqa: E402

from tinysesam.store import Store  # noqa: E402

alt_pfad = str(Path(tempfile.mkdtemp()) / "alt.db")
auth_alt, _ = _app(db_path=alt_pfad)
auth_alt.create_user("bestand", password="geheim12345")
altes_token = auth_alt.store.create_session(
    auth_alt.store.get_user_by_name("bestand")["id"], 3600, True, "password")
altes_handle = hashlib.sha256(altes_token.encode()).hexdigest()
auth_alt.store.db.close()

# zurück ins Format vor 0.18.0: Spalte heisst `token` und trägt den Klartext
roh = _sq.connect(alt_pfad)
roh.execute("ALTER TABLE session RENAME COLUMN token_hash TO token")
roh.execute("UPDATE session SET token=?", (altes_token,))
roh.commit()
roh.close()

neu_store = Store(alt_pfad)
spalten = {z[1] for z in neu_store.db.execute("PRAGMA table_info(session)")}
r.check("die alte Spalte `token` wird auf `token_hash` migriert",
        "token_hash" in spalten and "token" not in spalten,
        f"Spalten: {sorted(spalten)}")
r.check("bestehende Anmeldungen überleben die Umstellung",
        neu_store.get_session(altes_token) is not None,
        "das alte Cookie gilt nicht mehr — ein Update hätte alle Nutzer ausgeloggt")
r.check("und der Klartext ist danach aus der Datei verschwunden",
        [z["token_hash"] for z in neu_store._all("SELECT token_hash FROM session")] == [altes_handle],
        "der Klartext steht weiterhin in der Datenbank")


# ── Die Auth-Datenbank lag offen (0644) ───────────────────────────────────────
# Darin stehen Passwort-Hashes, TOTP-Geheimnisse und E-Mail-Adressen. Auf einem geteilten Host
# konnte sie jedes andere Konto lesen — WAL und SHM mit denselben Daten ebenso.
import os as _os  # noqa: E402
import stat as _stat  # noqa: E402

ordner = tempfile.mkdtemp()
pfad = str(Path(ordner) / "rechte.db")
auth_d, _ = _app(db_path=pfad)
auth_d.create_user("wer", password="geheim12345")
auth_d.store.create_session(auth_d.store.get_user_by_name("wer")["id"], 3600, True, "password")


def _modus(datei):
    return _stat.S_IMODE(_os.stat(datei).st_mode)


offen = {f: oct(_modus(Path(ordner) / f)) for f in sorted(_os.listdir(ordner))
         if _modus(Path(ordner) / f) & 0o077}
r.check("Datenbank, WAL und SHM sind nur für den eigenen Benutzer lesbar", not offen,
        f"für andere lesbar: {offen}")
r.check("die Prüfung sah überhaupt eine WAL-Datei",
        any(f.endswith("-wal") for f in _os.listdir(ordner)),
        f"nur {_os.listdir(ordner)} — dann sagt der Test über WAL/SHM nichts aus")

# Eine bestehende, zu offene Datenbank wird NICHT umgeschrieben (eine bewusste Gruppenfreigabe
# ist die Entscheidung des Betreibers) — aber sie wird laut benannt.
auth_d.store.db.close()
_os.chmod(pfad, 0o644)
puffer = io.StringIO()
haken = logging.StreamHandler(puffer)
log_ts = logging.getLogger("tinysesam")
log_ts.addHandler(haken)
try:
    Store(pfad)
finally:
    log_ts.removeHandler(haken)
r.check("eine bestehende, offene Datenbank wird gemeldet", "chmod 600" in puffer.getvalue(),
        f"keine Warnung: {puffer.getvalue()[:100]!r}")
r.check("und dabei nicht hinter dem Rücken umgestellt", _modus(pfad) == 0o644,
        f"auf {oct(_modus(pfad))} geändert — das überfährt eine bewusste Freigabe")


# ── API-Keys als zweite Tür: Aussperren sperrte sie nicht aus ─────────────────
# Ein Key hängt an keiner Sitzung. Wer ein Konto zurücksetzt oder sperrt, schloss bis 0.18.0 nur
# die Haustür. (Der Key eines DEAKTIVIERTEN Kontos war schon immer wertlos — `verify_api_key`
# prüft das Flag; hier geht es um Reset, Sperre und die Panik-Taste des Nutzers.)
auth_k, app_k = _app(apikey_enabled=True)
uid_k = auth_k.create_user("bot-halter", password="geheim12345")


def _key_gilt(auth_obj, schluessel):
    # verify_api_key gibt (user, roles) zurück — ein Tupel ist IMMER truthy. Nur [0] zählt.
    return auth_obj.verify_api_key(schluessel)[0] is not None


schluessel = auth_k.create_api_key(uid_k, "bot")["key"]
r.check("ein frischer API-Key gilt", _key_gilt(auth_k, schluessel), "schon der Ausgangspunkt fehlt")

# Selbst-Passwortwechsel lässt ihn absichtlich stehen — sonst legt jede Routine die Automatiken
# still. Aber der Zustand muss abfragbar sein, sonst ist „absichtlich" nur „unbemerkt".
auth_k.set_password(uid_k, "nochgeheimer99")
r.check("der eigene Passwortwechsel lässt Automatiken laufen", _key_gilt(auth_k, schluessel),
        "der Key ist tot — jede Passwort-Routine legt die Integrationen still")
r.check("und die Zahl der weiter gültigen Keys ist abfragbar",
        auth_k.store.count_active_api_keys(uid_k) == 1,
        f"gezählt: {auth_k.store.count_active_api_keys(uid_k)}")

# Der Massenwiderruf entwertet, und er sagt wie viele.
anzahl = auth_k.store.revoke_user_api_keys(uid_k)
r.check("der Massenwiderruf nennt die Zahl", anzahl == 1, f"meldete {anzahl}")
r.check("danach gilt der Key nicht mehr", not _key_gilt(auth_k, schluessel),
        "widerrufen und trotzdem gültig")
r.check("ein zweiter Widerruf zählt nichts doppelt",
        auth_k.store.revoke_user_api_keys(uid_k) == 0,
        "zählt schon widerrufene Keys erneut")

# Admin-Passwort-Reset: dort ist die Absicht Aussperren. CSRF ist für diesen Block abgeschaltet
# — der Schutz des Panels hat seine eigene Prüfung weiter oben, hier geht es um die Keys.
auth_a, _ = _app(apikey_enabled=True, csrf_enabled=False)
uid_a = auth_a.create_user("bot-halter", password="geheim12345")
zweit = auth_a.create_api_key(uid_a, "bot2")["key"]
admin_a = auth_a.create_user("chefin", password="geheim12345", is_admin=True)
app_a = FastAPI()
app_a.include_router(auth_a.router())          # Admin-Panel hängt per Auto-Mount unter /auth/admin
ca = TestClient(app_a)
ca.cookies.set(auth_a.cfg.session_cookie,
               auth_a.store.create_session(admin_a, 3600, True, "password"))

antwort = ca.post(f"/auth/admin/api/users/{uid_a}/password", json={"password": "ganzneu12345"})
r.check("der Admin-Reset läuft überhaupt durch", antwort.status_code == 200,
        f"HTTP {antwort.status_code}: {antwort.text[:120]}")
r.check("der Admin-Reset entwertet die API-Keys des Kontos", not _key_gilt(auth_a, zweit),
        "Key gilt weiter — Aussperren schloss nur die Haustür")
r.check("und sagt, wie viele es waren", antwort.json().get("api_keys_revoked") == 1,
        f"Antwort: {antwort.text[:120]}")

# Konto sperren: Keys sind über das `disabled`-Flag ohnehin tot — aber sie müssen auch
# widerrufen SEIN, sonst leben sie beim Entsperren wieder auf.
dritt = auth_a.create_api_key(uid_a, "bot3")["key"]
ca.post(f"/auth/admin/api/users/{uid_a}/disable", json={"disabled": True})
ca.post(f"/auth/admin/api/users/{uid_a}/disable", json={"disabled": False})
r.check("ein Key lebt nach Sperren und Entsperren nicht wieder auf", not _key_gilt(auth_a, dritt),
        "der Key gilt wieder — gesperrt und entsperrt ist kein Freifahrtschein")


# ── Admin-Aktionen ohne Akteur und ohne IP ────────────────────────────────────
# Das Protokoll hielt fest, DASS ein Konto gesperrt wurde — nicht von wem und von wo. Bei
# mehreren Admins ist das genau die Frage, die man hinterher stellt.
auth_p, _ = _app(csrf_enabled=False)
opfer_p = auth_p.create_user("betroffen", password="geheim12345")
chef_p = auth_p.create_user("chefin2", password="geheim12345", is_admin=True)
app_p = FastAPI()
app_p.include_router(auth_p.router())
cp = TestClient(app_p)
cp.cookies.set(auth_p.cfg.session_cookie,
               auth_p.store.create_session(chef_p, 3600, True, "password"))

cp.post(f"/auth/admin/api/users/{opfer_p}/disable", json={"disabled": True},
        headers={"X-Forwarded-For": "203.0.113.42"})
eintrag = next((z for z in auth_p.store.recent_audit(50) if z["event"] == "user_disable"), None)
r.check("das Sperren steht überhaupt im Protokoll", eintrag is not None,
        "keine Zeile — dann sagt der Test über den Rest nichts")
r.check("und nennt den Admin, der es getan hat",
        bool(eintrag) and eintrag["username"] == "chefin2",
        f"username={eintrag['username'] if eintrag else None!r}")
r.check("und die IP, von der aus", bool(eintrag) and bool(eintrag["ip"]),
        f"ip={eintrag['ip'] if eintrag else None!r}")

# Nicht nur diese eine Route: auch der Passwort-Reset.
cp.post(f"/auth/admin/api/users/{opfer_p}/password", json={"password": "ganzneu12345"})
reset = next((z for z in auth_p.store.recent_audit(50) if z["event"] == "user_password_reset"), None)
r.check("auch der Admin-Passwort-Reset nennt Akteur und IP",
        bool(reset) and reset["username"] == "chefin2" and bool(reset["ip"]),
        f"{dict(reset) if reset else None}")


# ── Der Wächter, der ab der ersten Logrotation nicht mehr wacht ───────────────
# `logging.FileHandler` hält den Inode offen. logrotate benennt um und legt neu an — ab da
# schreibt der Prozess in die UMBENANNTE Datei, die fail2ban-Jail liest die leere neue.
import os as _os2  # noqa: E402

from tinysesam.security import attach_security_log, seclog  # noqa: E402

log_ordner = tempfile.mkdtemp()
log_datei = str(Path(log_ordner) / "security.log")
attach_security_log(log_datei)
seclog.warning("failed login user=vorher ip=203.0.113.1 method=password")
_os2.rename(log_datei, log_datei + ".1")          # genau das macht logrotate
open(log_datei, "w").close()
seclog.warning("failed login user=nachher ip=203.0.113.2 method=password")

r.check("nach einer Logrotation landet die nächste Zeile in der NEUEN Datei",
        "nachher" in open(log_datei, encoding="utf-8").read(),
        "sie steht in der umbenannten Datei — die Jail liest ab jetzt ins Leere")
r.check("und nicht mehr in der rotierten",
        "nachher" not in open(log_datei + ".1", encoding="utf-8").read(),
        "der alte Inode bekommt weiter Zeilen")


# ── Der App-Lockout blendete fail2ban aus ────────────────────────────────────
# Solange gesperrt war, rief niemand mehr `record_login()`: Die App antwortete 429 und schrieb
# keine Zeile. Das Log verstummte genau dann, wenn die IP hätte gebannt werden sollen.
auth_l, _ = _app()
auth_l.create_user("ziel3", password="geheim12345")
for _ in range(10):
    auth_l.record_login("ziel3", "203.0.113.77", success=False, method="password")

puffer_l = io.StringIO()
haken_l = logging.StreamHandler(puffer_l)
seclog.addHandler(haken_l)
try:
    gesperrt = auth_l.is_locked("ziel3", "203.0.113.77")
finally:
    seclog.removeHandler(haken_l)
zeile_l = puffer_l.getvalue()

r.check("das Konto ist überhaupt gesperrt", gesperrt, "kein Lockout — dann misst der Test nichts")
r.check("die Abweisung schreibt eine Zeile ins Sicherheits-Log", "failed login" in zeile_l,
        f"Log schweigt: {zeile_l[:80]!r} — fail2ban sieht keinen Grund zu bannen")
r.check("und nennt den Grund", "reason=lockout" in zeile_l, f"ohne Grund: {zeile_l[:100]!r}")
r.check("die Zeile passt auf den mitgelieferten fail2ban-Filter",
        bool(re.search(r"failed login user=.* ip=(\S+) method=.*", zeile_l)),
        f"Filter greift nicht: {zeile_l[:100]!r}")

# Auch das Rate-Limit darf nicht stumm abweisen.
puffer_r = io.StringIO()
haken_r = logging.StreamHandler(puffer_r)
seclog.addHandler(haken_r)
try:
    for _ in range(int(auth_l.sec("rate_limit_max")) + 2):
        auth_l.rate_ok("203.0.113.78")
finally:
    seclog.removeHandler(haken_r)
r.check("auch ein Rate-Limit-Treffer steht im Log",
        "reason=ratelimit" in puffer_r.getvalue(),
        f"stumm: {puffer_r.getvalue()[:80]!r}")


# ── Hinter dem Proxy: alle Nutzer unter einer IP ──────────────────────────────
# Im Container ist der Proxy ein anderer Container, also nicht 127.0.0.1. Die Vorgabe passt
# dann nicht, X-Forwarded-For wird verworfen, und JEDER erscheint unter der Proxy-IP: Sperre
# und Rate-Limit wirken ab da kollektiv. Nichts davon sieht nach einem Fehler aus.
#
# Als Proxy-Adresse steht hier 192.0.2.x (RFC 5737, für Dokumentation) statt einer echten
# Docker-Bridge-Adresse: Das Verhalten hängt allein daran, ob der Peer in `trusted_proxies`
# steht, nicht am Adressbereich — und der Hygiene-Test fängt nackte RFC1918-Hostadressen, zu
# Recht. In einem echten Compose steht dort das Netz des Proxys (s. deploy/forward-auth/).
from tinysesam import security as _sec  # noqa: E402


class _Anfrage:
    def __init__(self, peer, xff=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff} if xff else {}


def _mit_log(fn):
    """(Rückgabe, Log-Text) — und der Merker wird vorher geleert, damit die Prüfungen sich
    nicht gegenseitig die Meldung wegnehmen (jede Warnung kommt nur einmal je Peer)."""
    _sec._GEMELDETE_PEERS.clear()
    puffer = io.StringIO()
    haken = logging.StreamHandler(puffer)
    _sec.seclog.addHandler(haken)
    try:
        return fn(), puffer.getvalue()
    finally:
        _sec.seclog.removeHandler(haken)


echte_ip, log_a = _mit_log(lambda: _sec.client_ip(_Anfrage("192.0.2.5", "203.0.113.9"),
                                                  ["127.0.0.1/32"]))
r.check("mit der Vorgabe hinter einem Container-Proxy bleibt es bei der Proxy-IP",
        echte_ip == "192.0.2.5", f"ergab {echte_ip} — dann misst der Test das Falsche")
r.check("...und das wird gemeldet statt still hingenommen",
        "trusted_proxies" in log_a and "ignoriert" in log_a,
        f"kein Hinweis: {log_a[:90]!r}")

# 0.0.0.0/0 klingt großzügig und entwertet XFF vollständig: Gilt jede Adresse als Proxy,
# bleibt keine als Client übrig.
alles, log_b = _mit_log(lambda: _sec.client_ip(_Anfrage("192.0.2.7", "203.0.113.9"),
                                               ["0.0.0.0/0"]))
r.check("0.0.0.0/0 liefert NICHT die Client-IP", alles == "192.0.2.7",
        f"ergab {alles} — dann wäre XFF fälschbar")
r.check("...und auch das wird gemeldet", "entwertet" in log_b,
        f"kein Hinweis: {log_b[:90]!r}")

# Richtig konfiguriert kommt die echte Adresse durch — und dann gibt es nichts zu melden.
richtig, log_c = _mit_log(lambda: _sec.client_ip(_Anfrage("192.0.2.5", "203.0.113.9"),
                                                 ["192.0.2.0/24"]))
r.check("mit dem Netz des Proxys kommt die echte Client-IP an", richtig == "203.0.113.9",
        f"ergab {richtig}")
r.check("und der Normalbetrieb schweigt", log_c.strip() == "",
        f"warnt ohne Anlass: {log_c[:90]!r}")

# Die Meldung kommt einmal je Peer, nicht pro Request — sonst erschlägt sie das Log.
_sec._GEMELDETE_PEERS.clear()
puffer_w = io.StringIO()
haken_w = logging.StreamHandler(puffer_w)
_sec.seclog.addHandler(haken_w)
try:
    for _ in range(5):
        _sec.client_ip(_Anfrage("192.0.2.9", "203.0.113.9"), ["127.0.0.1/32"])
finally:
    _sec.seclog.removeHandler(haken_w)
# Gezählt werden MELDUNGEN, nicht Wörter: Die Meldung nennt `trusted_proxies` selbst zweimal
# (einmal als Befund, einmal im Rat), ein Wort-Zähler stünde also immer auf 2.
_zeilen = [z for z in puffer_w.getvalue().splitlines() if "X-Forwarded-For" in z]
r.check("die Warnung kommt einmal je Peer, nicht bei jedem Request", len(_zeilen) == 1,
        f"{len(_zeilen)} Meldungen für 5 Anfragen")

# SSO- und Passkey-Login schrieben die rohe Peer-IP in die Sitzung und ins Protokoll.
for modul in ("oidc.py", "webauthn_.py"):
    quelle = (Path(__file__).resolve().parent.parent / "tinysesam" / modul).read_text(encoding="utf-8")
    code = "\n".join(z for z in quelle.splitlines() if not z.lstrip().startswith("#"))
    r.check(f"{modul} nimmt client_ip, nicht die rohe Peer-IP",
            "request.client.host" not in code and "client_ip(request)" in code,
            "greift wieder direkt auf request.client zu — hinter einem Proxy ist das der Proxy")

# Und das mitgelieferte Compose darf nicht vormachen, was hier gerade widerlegt wurde.
compose = (Path(__file__).resolve().parent.parent / "deploy" / "forward-auth"
           / "docker-compose.yml").read_text(encoding="utf-8")
r.check("das Compose-Beispiel setzt trusted_proxies nicht auf 0.0.0.0/0",
        'TINYSESAM_TRUSTED_PROXIES: "0.0.0.0/0"' not in compose,
        "das Beispiel macht jede Client-IP zur Proxy-IP")


# ── Forward-Auth: der Anzeigename ging roh in einen HTTP-Header ───────────────
# Der Name kommt bei OIDC/SAML vom fremden IdP. Zwei Dinge brachen daran: ein Zeilenumbruch
# (Header-Injection — h11 fängt sie ab, aber mit Abbruch, also Selbstsperre) und ein Name
# jenseits von Latin-1 (500, ganz ohne Angreifer).
auth_h, _ = _app(forward_auth_enabled=True)
uid_h = auth_h.create_user("intl", password="geheim12345")


def _kopfwert(roh):
    auth_h.store._exec("UPDATE users SET display_name=? WHERE id=?", (roh, uid_h))
    kopf = auth_h.forward_response_headers(auth_h.store.get_user(uid_h))
    return kopf["Remote-Name"]


boes = _kopfwert("Bose\r\nX-Remote-Groups: admin")
r.check("Zeilenumbrüche fliegen aus dem Header-Wert",
        "\r" not in boes and "\n" not in boes, f"{boes!r}")

# Der Wert muss durch einen ECHTEN HTTP-Serialisierer gehen, nicht nur durch den TestClient:
# der In-Process-Client reicht auch durch, was auf der Leitung nie ankäme.
import h11  # noqa: E402


def _geht_raus(wert):
    try:
        h11.Response(status_code=200, headers=[("Remote-Name", wert.encode("latin-1"))])
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


for roh, was in (("Bose\r\nX-Remote-Groups: admin", "Zeilenumbruch"),
                 ("Müller", "Umlaut"), ("Иван", "Kyrillisch"), ("测试 Wang", "Chinesisch")):
    wert = _kopfwert(roh)
    geht, fehler = _geht_raus(wert)
    r.check(f"{was} im Anzeigenamen kommt durch den HTTP-Serialisierer", geht, fehler)

# Und verlustfrei: die App liest den Header als UTF-8 und hat den Namen zurück.
for roh in ("Müller", "Иван", "测试 Wang", "alice"):
    zurueck = _kopfwert(roh).encode("latin-1").decode("utf-8")
    r.check(f"{roh!r} kommt beim Empfänger unverändert an", zurueck == roh,
            f"wurde {zurueck!r}")

# Die Kodierung ist EINHEITLICH — sonst wüsste keine App, was sie gerade hat.
r.check("auch ein Latin-1-fähiger Name geht als UTF-8 über die Leitung",
        _kopfwert("Müller").encode("latin-1") == "Müller".encode("utf-8"),
        "mal Latin-1, mal UTF-8 — die App kann es nicht auseinanderhalten")


# ── Ein Sicherheitsschalter, der nie etwas tat ───────────────────────────────
# `totp_required` stand in der Config, in beiden READMEs („2FA erzwingen") und auf der Website —
# und wurde an keiner Stelle im Code gelesen. Wer ihn setzte, glaubte den zweiten Faktor
# erzwungen zu haben und hatte ihn nicht.
gebaut, text = _baut(totp_required=True)
r.check("totp_required=True wird abgewiesen statt stumm ignoriert", not gebaut,
        "die Instanz baut — der Betreiber glaubt weiter an einen Schutz, den es nicht gibt")
r.check("und die Meldung nennt den Weg, der wirklich greift", "login_chain" in text,
        f"ohne Hinweis: {text[:90]!r}")

# Der Schalter darf auch nirgends mehr beworben werden. `web/` gibt es nur im Repo, nicht im
# Quellpaket — geprüft wird, was da ist, und die Prüfung sagt, was sie gesehen hat.
wurzel = Path(__file__).resolve().parent.parent
gesehen = []
for datei in ("README.md", "i18n/README.de.md", "web/flows.py"):
    pfad = wurzel / datei
    if not pfad.exists():
        continue
    gesehen.append(datei)
    r.check(f"{datei} bewirbt totp_required nicht mehr",
            "totp_required" not in pfad.read_text(encoding="utf-8"),
            "der tote Schalter wird weiter als 2FA angepriesen")
r.check("dabei waren mindestens beide READMEs",
        {"README.md", "i18n/README.de.md"} <= set(gesehen), f"nur gesehen: {gesehen}")

# Die Faktor-Kette ist der beworbene Weg — sie muss also gehen.
gebaut, text = _baut(login_chain=["password", "totp"], login_chain_strict=True)
r.check("die empfohlene Faktor-Kette baut", gebaut, f"empfohlen und kaputt: {text[:110]}")


# ── set_template nahm Namen an, die es nicht gab ─────────────────────────────
# Der Docstring nannte 'magic_sent' und 'resource_pin' — beide hat es nie gegeben — und liess
# sieben echte Seiten weg. Ein Tippfehler blieb folgenlos-still: eingetragen, nie aufgerufen.
auth_tpl, _ = _app()
try:
    auth_tpl.set_template("magic_sent", lambda *a, **k: "x")
    still = True
except ValueError:
    still = False
r.check("ein unbekannter Seitenname fliegt auf", not still,
        "wird angenommen und nie aufgerufen — man sucht den Fehler woanders")

try:
    auth_tpl.set_template("login", lambda *a, **k: "x")
    echte_geht = True
except ValueError:
    echte_geht = False
r.check("ein echter Seitenname geht weiterhin", echte_geht, "die Liste ist zu eng")

# Die Liste im Code muss zu den Seiten passen, die render_page wirklich bedient — sonst
# veraltet sie wieder still.
quelle = "\n".join((wurzel / "tinysesam" / f).read_text(encoding="utf-8")
                    for f in ("router.py", "manager.py", "admin.py"))
gerendert = set(re.findall(r'render_page\(\s*"([a-z_]+)"', quelle))
fehlend = sorted(gerendert - set(auth_tpl.SEITEN))
r.check("jede gerenderte Seite steht in TinySesam.SEITEN", not fehlend,
        f"nicht ersetzbar, obwohl es sie gibt: {fehlend}")


# ── Deutsche Fehlertexte bei lang="en" ───────────────────────────────────────
# 32 HTTP-Antworten trugen festen deutschen Text — auch in einer Installation, die auf Englisch
# steht. Die UI war zweisprachig, die Antworten an Maschinen und Proxys nicht.
auth_en, app_en = _app(lang="en")
auth_en.create_user("someone", password="geheim12345")
cen = TestClient(app_en)

# Echte Antworten messen, nicht die Übersetzungstabelle abfragen. Dafür braucht es eine
# angemeldete Sitzung: Ohne sie antwortet jeder Endpunkt mit 401 „Unauthorized", und der Test
# sähe grün aus, ohne je eine übersetzte Meldung gesehen zu haben.
def _antworten(auth_obj, app_obj, benutzer):
    klient = TestClient(app_obj)
    uid = auth_obj.store.get_user_by_name(benutzer)["id"]
    klient.cookies.set(auth_obj.cfg.session_cookie,
                       auth_obj.store.create_session(uid, 3600, True, "password"))
    return [
        ("CSRF fehlt", klient.post("/auth/apikeys", json={"name": "x"})),
        ("Ressource unbekannt", klient.get("/auth/resource/gibtsnicht")),
    ]


antworten = _antworten(auth_en, app_en, "someone")
umlaute = "äöüßÄÖÜ"
deutsch = [f"{was}: {a.text[:70]}" for was, a in antworten
           if any(z in (a.text or "") for z in umlaute)
           or "nötig" in (a.text or "") or "ungültig" in (a.text or "")]
r.check("bei lang='en' kommt kein deutscher Text aus den Endpunkten", not deutsch,
        " | ".join(deutsch))
r.check("und die Antworten tragen überhaupt eine eigene Meldung",
        all(a.status_code >= 400 for _, a in antworten)
        and any("Unauthorized" not in (a.text or "") for _, a in antworten),
        f"Status {[a.status_code for _, a in antworten]}, Texte "
        f"{[(a.text or '')[:40] for _, a in antworten]} — misst sonst nichts")

# Und auf Deutsch muss weiterhin Deutsch kommen, sonst wäre die Übersetzung nur verschoben.
auth_de, app_de = _app(lang="de")
auth_de.create_user("jemand", password="geheim12345")
deutsche = " ".join((a.text or "") for _, a in _antworten(auth_de, app_de, "jemand"))
r.check("bei lang='de' kommt weiterhin Deutsch",
        any(z in deutsche for z in umlaute) or "nötig" in deutsche,
        f"{deutsche[:100]!r}")

# Hygiene: kein roher Text mehr in einer HTTPException — sonst wächst die Lücke von selbst nach.
roh = []
for modul in ("manager.py", "router.py", "admin.py", "oidc.py", "webauthn_.py", "saml_.py"):
    quelle = (Path(__file__).resolve().parent.parent / "tinysesam" / modul).read_text(encoding="utf-8")
    for nr, zeile in enumerate(quelle.splitlines(), 1):
        if re.search(r'HTTPException\(\s*\d+\s*,\s*[fr]?"', zeile):
            roh.append(f"{modul}:{nr}")
r.check("keine HTTPException mit festem Text mehr", not roh, ", ".join(roh[:5]))


# ── Recovery-Codes trugen 48 Bit ─────────────────────────────────────────────
# Ein Recovery-Code ERSETZT den zweiten Faktor und gilt, bis er benutzt wird. Ein TOTP-Code hat
# nur eine Million Möglichkeiten, ist aber nach 30 Sekunden wertlos — der Vergleich trägt nicht.
auth_rc, _ = _app()
uid_rc = auth_rc.create_user("rc", password="geheim12345")
codes = auth_rc.generate_recovery_codes(uid_rc)
hexzeichen = sum(1 for z in codes[0] if z in "0123456789abcdef")
r.check("ein Recovery-Code trägt mindestens 64 Bit", hexzeichen * 4 >= 64,
        f"{codes[0]} = {hexzeichen * 4} Bit")
r.check("die Codes sind untereinander verschieden", len(set(codes)) == len(codes),
        f"{len(codes)} Codes, {len(set(codes))} verschiedene")
r.check("und ein frisch erzeugter Code löst den zweiten Faktor aus",
        auth_rc.verify_recovery_code(uid_rc, codes[0]),
        "der Code wird nicht angenommen — dann misst der Test nur Zeichen")
r.check("ein Code gilt genau einmal", not auth_rc.verify_recovery_code(uid_rc, codes[0]),
        "derselbe Code geht ein zweites Mal")


# ── Es gab keine Fehlertypen, auf die man reagieren kann ─────────────────────
# Geworfen wurde `ValueError` (Konfiguration) und `RuntimeError` (fehlendes Extra). Wer beim
# Starten unterscheiden wollte, ob die Konfiguration falsch ist oder ein Paket fehlt, musste den
# Meldungstext lesen — und der ist seit dieser Version übersetzt.
from tinysesam import ConfigError, MissingExtra, TinySesamError  # noqa: E402

try:
    _app(totp_required=True)
    art = None
except Exception as e:
    art = e
r.check("ein Konfigurationsfehler ist ein ConfigError", isinstance(art, ConfigError),
        f"{type(art).__name__}")
r.check("...und weiterhin ein ValueError (bestehender Code fängt ihn)",
        isinstance(art, ValueError), "bestehendes `except ValueError` bricht")
r.check("...und ein TinySesamError", isinstance(art, TinySesamError), f"{type(art).__mro__}")

# Der Extra-Wächter, zweistufig. Werfen darf nur, wo es nie falsch sein kann: Ein Client ist
# ersetzbar (`auth.ldap = eigener_client`, so arbeiten vier eigene Suiten), also bricht der
# Aufbau NICHT ab — er warnt. Geworfen wird am lazy Import, also beim ersten echten Gebrauch.
import importlib  # noqa: E402


class _Blockiert:
    """Ein Import-Finder, der genau ein Modul „nicht findet"."""

    def __init__(self, name):
        self.name = name

    def find_spec(self, fullname, pfad=None, ziel=None):
        if fullname == self.name or fullname.startswith(self.name + "."):
            raise ModuleNotFoundError(f"No module named '{fullname}'", name=fullname)
        return None


def _ohne_modul(name, fn):
    """`fn()` ausführen, als wäre `name` nicht installiert."""
    blocker = _Blockiert(name)
    sys.meta_path.insert(0, blocker)
    weg = {n: m for n, m in list(sys.modules.items()) if n == name or n.startswith(name + ".")}
    for n in weg:
        del sys.modules[n]
    try:
        return fn()
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(weg)
        importlib.invalidate_caches()


puffer_x = io.StringIO()
haken_x = logging.StreamHandler(puffer_x)
_sec.seclog.addHandler(haken_x)
try:
    auth_x, _ = _ohne_modul("ldap3", lambda: _app(
        ldap_enabled=True, ldap_url="ldap://ldap.example.com", password_enabled=False))
    gebaut_x = True
except Exception as e:
    auth_x, gebaut_x = None, e
finally:
    _sec.seclog.removeHandler(haken_x)

r.check("ein fehlendes Extra bricht den Aufbau NICHT ab", gebaut_x is True,
        f"{type(gebaut_x).__name__} — dann kann niemand mehr seinen eigenen Client setzen")
r.check("...wird aber beim Start gemeldet", "tinysesam[ldap]" in puffer_x.getvalue(),
        f"schweigt: {puffer_x.getvalue()[:90]!r}")

# Und beim ersten echten Gebrauch ein lesbarer Fehler statt eines nackten ModuleNotFoundError.
from tinysesam.ldap_ import LDAPClient  # noqa: E402

klient = LDAPClient(auth_x.cfg if auth_x else None)
try:
    _ohne_modul("ldap3", klient._server)
    gebrauch = None
except Exception as e:
    gebrauch = e
r.check("beim Gebrauch fliegt ein MissingExtra", isinstance(gebrauch, MissingExtra),
        f"{type(gebrauch).__name__}: {str(gebrauch)[:70]}")
r.check("...mit maschinenlesbarem Extra-Namen", getattr(gebrauch, "extra", None) == "ldap",
        f"extra={getattr(gebrauch, 'extra', None)!r}")
r.check("...und weiterhin ein RuntimeError", isinstance(gebrauch, RuntimeError),
        "bestehendes `except RuntimeError` bricht")

# Gegenprobe: Wer das Verfahren unvollständig lässt, bringt den Client selbst mit.
gebaut, text = _baut(ldap_enabled=True)
r.check("ein halb konfiguriertes Verfahren bleibt baubar (eigener Client)", gebaut,
        f"abgewiesen: {text[:110]}")

# Nach der Gegenprobe muss der Normalfall wieder bauen — sonst hätte der Test die Tabelle
# kaputt zurückgegeben und alles Folgende wäre Unsinn.
gebaut, _ = _baut()
r.check("die Tabelle ist nach der Gegenprobe wieder heil", gebaut,
        "der Test hat den Zustand nicht sauber zurückgesetzt")


# ── Die Datenbank trug keinen Schema-Stempel ─────────────────────────────────
# Welchen Stand eine Datei hat, war nur an ihren Spaltennamen zu erraten. Eine Datei aus einer
# NEUEREN Fassung öffnete eine ältere Version stillschweigend — mit Tabellen, die sie nicht
# kennt, und Schreibvorgängen, die Lücken hinterlassen.
stempel_pfad = str(Path(tempfile.mkdtemp()) / "stempel.db")
st = Store(stempel_pfad)
gestempelt = int(st.db.execute("PRAGMA user_version").fetchone()[0] or 0)
r.check("eine frische Datenbank trägt die Schema-Version",
        gestempelt == Store.SCHEMA_VERSION and gestempelt > 0,
        f"user_version={gestempelt}, erwartet {Store.SCHEMA_VERSION}")
st.db.close()

# Eine Datei aus der Zukunft muss sich melden.
roh_st = _sq.connect(stempel_pfad)
roh_st.execute(f"PRAGMA user_version = {Store.SCHEMA_VERSION + 50}")
roh_st.commit()
roh_st.close()
puffer_st = io.StringIO()
haken_st = logging.StreamHandler(puffer_st)
log_st = logging.getLogger("tinysesam")
log_st.addHandler(haken_st)
try:
    zukunft = Store(stempel_pfad)
finally:
    log_st.removeHandler(haken_st)
r.check("eine Datei aus einer neueren Version wird gemeldet",
        "neueren Version" in puffer_st.getvalue(),
        f"schweigt: {puffer_st.getvalue()[:80]!r}")
r.check("...und der höhere Stempel wird NICHT zurückgesetzt",
        int(zukunft.db.execute("PRAGMA user_version").fetchone()[0]) == Store.SCHEMA_VERSION + 50,
        "die Version wurde heruntergestempelt — beim nächsten Öffnen fehlt die Warnung")


# ── Widersprüche fielen erst beim Login auf ──────────────────────────────────
# Eine App ohne eine einzige Anmelde-Methode startete klaglos; eine `login_chain`, die ein
# abgeschaltetes Verfahren nennt, ist unerfüllbar und schickt den Nutzer im Kreis.
gebaut, text = _baut(password_enabled=False)
r.check("eine Instanz ohne jede Anmelde-Methode wird abgewiesen", not gebaut,
        "baut — niemand kann sich anmelden, und nichts sagt es")
r.check("...mit dem Hinweis, welche Schalter es gäbe", "password_enabled=True" in text,
        f"{text[:90]!r}")

gebaut, text = _baut(login_chain=["password", "pin"], pin_enabled=False)
r.check("eine unerfüllbare Faktor-Kette wird abgewiesen", not gebaut,
        "baut — der Nutzer landet in einer Schleife")
r.check("...und nennt den blockierenden Schritt", "pin_enabled=False" in text, f"{text[:90]!r}")

gebaut, text = _baut(login_chain=["password", "gibtsnicht"])
r.check("ein unbekannter Schritt in der Kette wird abgewiesen", not gebaut,
        "ein Tippfehler in der Kette bliebe folgenlos-still")

# Alle Befunde auf einmal — wer drei Dinge falsch hat, soll sie einmal lesen.
gebaut, text = _baut(password_enabled=False, login_chain=["password", "pin"], pin_enabled=False)
r.check("mehrere Widersprüche werden zusammen gemeldet", text.count("\n  - ") >= 2,
        f"nur einer: {text[:120]!r}")

# Was später noch kommen kann, ist eine Warnung — kein Abbruch. `set_mailer` nach dem
# Konstruktor ist eine völlig übliche Reihenfolge.
puffer_k = io.StringIO()
haken_k = logging.StreamHandler(puffer_k)
_sec.seclog.addHandler(haken_k)
try:
    gebaut, text = _baut(magiclink_enabled=True)
finally:
    _sec.seclog.removeHandler(haken_k)
r.check("ein fehlender Mailer verhindert den Start NICHT", gebaut,
        f"bricht ab: {text[:90]} — set_mailer() kommt oft erst danach")
r.check("...wird aber gemeldet", "smtp_host" in puffer_k.getvalue(),
        f"schweigt: {puffer_k.getvalue()[:80]!r}")

# Und der Normalfall darf weder brechen noch lärmen.
puffer_n = io.StringIO()
haken_n = logging.StreamHandler(puffer_n)
_sec.seclog.addHandler(haken_n)
try:
    gebaut, text = _baut()
finally:
    _sec.seclog.removeHandler(haken_n)
r.check("die Vorgabe-Konfiguration baut ohne Befund", gebaut, text[:110])
r.check("...und ohne Konfigurations-Warnung", "Konfiguration:" not in puffer_n.getvalue(),
        f"warnt ohne Anlass: {puffer_n.getvalue()[:90]!r}")


# ── complete_mfa versprach mehr, als die Methode tut ─────────────────────────
# Der Docstring nannte den Namen selbst „rückwärtskompatibel" — und er blieb trotzdem der
# einzige. MFA ist die ganze Kette; die Methode hängt genau einen Faktor an.
auth_cm, _ = _app()
r.check("es gibt den klaren Namen complete_totp", hasattr(auth_cm, "complete_totp"),
        "nur der alte Name — dann ist nichts gewonnen")
r.check("der alte Name complete_mfa bleibt erhalten", hasattr(auth_cm, "complete_mfa"),
        "entfernt — das bricht bestehende Aufrufe für einen Namen")

# Und der Alias muss wirklich dasselbe tun, nicht nur existieren.
uid_cm = auth_cm.create_user("cm", password="geheim12345")
tok_alt = auth_cm.store.create_session(uid_cm, 3600, False, "password")
auth_cm.complete_mfa(tok_alt)
tok_neu = auth_cm.store.create_session(uid_cm, 3600, False, "password")
auth_cm.complete_totp(tok_neu)
import json as _json  # noqa: E402

faktoren = [sorted(_json.loads(auth_cm.store.get_session(t)["factors_done"] or "[]"))
            for t in (tok_alt, tok_neu)]
r.check("beide Namen hängen denselben Faktor an", faktoren[0] == faktoren[1] == ["totp"],
        f"alt={faktoren[0]} neu={faktoren[1]} — ein Alias, der etwas anderes tut, ist schlimmer "
        "als zwei Methoden")

sys.exit(r.done())
