"""Nachgestellte Angriffe aus der Reifeprüfung vom 2026-09-21 (und den Runden danach).

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

from tinysesam import ConfigError, StateError, TinySesam, TinySesamConfig  # noqa: E402
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

# Seit dem zweiten Audit wird der Versuch schon beim AUSSTELLEN abgewiesen, nicht erst beim
# Prüfen. Grund: Ein auf `[]` zusammengeschrumpfter Scope hiess in der Datenbank „kein Scope,
# erbt alles" — die Beschneidung hätte den Key also mächtiger gemacht statt schwächer. Ein
# Fehler ist hier die einzige ehrliche Antwort; was gemeint war, weiss nur der Aufrufer.
try:
    auth.create_api_key(nutzer["id"], name="probe", roles=["buchhaltung"])
    abgewiesen = None
except ConfigError as e:
    abgewiesen = e
r.check("ein Key mit einer Rolle, die der Besitzer nicht hat, entsteht gar nicht erst",
        abgewiesen is not None,
        "der Key wurde ausgestellt — und ein leerer Scope erbt in der Datenbank ALLE Rollen")
r.check("und die Meldung nennt die verlangte Rolle", "buchhaltung" in str(abgewiesen or ""),
        f"{str(abgewiesen)[:80]!r}")

# Der Key darf auch über die HTTP-Route nicht entstehen — dort kommt der Wunsch her.
with TestClient(app) as c:
    c.cookies.set(auth.cfg.session_cookie,
                  auth.store.create_session(nutzer["id"], 3600, True, "password"))
    ueber_http = c.post("/auth/apikeys", json={"name": "probe", "roles": ["buchhaltung"]})
r.check("auch über POST /auth/apikeys entsteht er nicht", ueber_http.status_code >= 400,
        f"HTTP {ueber_http.status_code} — der Weg, über den der Angriff lief")

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

# Dieselbe Unterschiebung per Cookie-Tossing (A-1): Eine Nachbar-Subdomain kann ein Cookie
# `Domain=.example.com` setzen — aber keines mit `__Host-`. Das Flow-Cookie muss also das
# Präfix tragen, sonst schiebt sie dem Opfer den Flow des Angreifers samt Wert unter, und das
# Opfer landet trotz gepräfixtem Sitzungs-Cookie im Konto des Angreifers.
auth_s, app_s = _app(oidc_enabled=True, oidc_issuer="https://idp.example.invalid",
                     oidc_client_id="probe", oidc_client_secret="geheim", cookie_secure=True,
                     base_url="https://auth.example.com")
auth_s.oidc._meta = dict(auth_o.oidc._meta)
with TestClient(app_s, base_url="https://auth.example.com") as angreifer:
    start = angreifer.get("/auth/oidc/start", follow_redirects=False)
    flow_wert = angreifer.cookies.get("__Host-tinysesam_oidc_flow")
r.check("mit Secure heisst das Flow-Cookie __Host-tinysesam_oidc_flow", bool(flow_wert),
        f"gesetzt: {start.headers.get('set-cookie', '—')[:60]}")
state_s = parse_qs(urlparse(start.headers["location"]).query).get("state", [""])[0]
with TestClient(app_s, base_url="https://auth.example.com") as opfer_b:
    opfer_b.cookies.set("tinysesam_oidc_flow", flow_wert or "")   # was eine Nachbar-Subdomain setzen kann
    antwort = opfer_b.get(f"/auth/oidc/callback?code=egal&state={state_s}", follow_redirects=False)
r.check("ein ungepräfixtes (untergeschobenes) Flow-Cookie bindet den Callback nicht",
        antwort.status_code == 400 and auth_s.t("api.oidc_browser") in antwort.text,
        f"HTTP {antwort.status_code} {antwort.text[:80]} — Login-CSRF per Cookie-Tossing")
# Gegenprobe: Mit dem echten, gepräfixten Cookie kommt der Callback an der Bindung vorbei
# (und scheitert erst am Tausch mit dem attrappenlosen IdP) — sonst prüfte der Fall oben nichts.
with TestClient(app_s, base_url="https://auth.example.com") as selbst:
    start = selbst.get("/auth/oidc/start", follow_redirects=False)
    state_s = parse_qs(urlparse(start.headers["location"]).query).get("state", [""])[0]
    try:
        antwort = selbst.get(f"/auth/oidc/callback?code=egal&state={state_s}", follow_redirects=False)
        text = antwort.text
    except Exception as e:      # der Tausch gegen idp.example.invalid darf werfen
        text = repr(e)
r.check("…das gepräfixte Cookie des eigenen Browsers bindet ihn weiterhin",
        auth_s.t("api.oidc_browser") not in text, text[:80])
r.check("SAML- und Passkey-Flow-Cookie tragen das Präfix ebenso",
        auth_s.flow_cookie_name("tinysesam_saml_flow") == "__Host-tinysesam_saml_flow"
        and auth_s.flow_cookie_name("tinysesam_waflow") == "__Host-tinysesam_waflow")

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
                     signup_require_email=True, signup_verify_email=True,
                     # Pflicht seit der base_url-Nacharbeit; ohne sie scheiterte der Aufbau aus
                     # einem Grund, der mit dem Erst-Admin-Wächter nichts zu tun hat.
                     base_url="https://auth.example.com")
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
        "nachher" in Path(log_datei).read_text(encoding="utf-8"),
        "sie steht in der umbenannten Datei — die Jail liest ab jetzt ins Leere")
r.check("und nicht mehr in der rotierten",
        "nachher" not in Path(log_datei + ".1").read_text(encoding="utf-8"),
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
    # `password_enabled` bleibt an: LDAP prüft Passwörter und erfüllt den Faktor `password` —
    # ohne den Schalter gäbe es keine einzige Anmelde-Methode, und die Konfigurationsprüfung
    # bricht (zu Recht) vorher ab. Hier geht es um das fehlende Extra, nicht um das.
    # `ldap_allow_plaintext=True`: Seit F-12 ist `ldap://` ohne TLS ein Aufbaufehler. Hier soll
    # aber das FEHLENDE EXTRA gemessen werden, nicht der Transport — ohne den Schalter bräche
    # der Aufbau aus dem anderen Grund ab und die Prüfung darunter wäre grün, ohne zu messen.
    auth_x, _ = _ohne_modul("ldap3", lambda: _app(
        ldap_enabled=True, ldap_url="ldap://ldap.example.com", ldap_allow_plaintext=True))
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
# Konstruktor ist eine völlig übliche Reihenfolge. `base_url` ist der Gegenfall und steht
# deshalb hier: Sie muss beim Aufbau stehen (Fehler, nicht Warnung — s. R4-01-Nacharbeit),
# sonst liefe „Passwort vergessen" still ins Leere.
puffer_k = io.StringIO()
haken_k = logging.StreamHandler(puffer_k)
_sec.seclog.addHandler(haken_k)
try:
    gebaut, text = _baut(magiclink_enabled=True, base_url="https://auth.example.com")
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


# ── Der Host-Header vergiftete Reset-, Anmelde- und Bestätigungslink (R4-01/R8-4) ──────────
# Angriff: Der Angreifer stößt „Passwort vergessen" für ein FREMDES Postfach an und setzt dabei
# den rohen `Host`-Header. TinySesam baute die Mail-Adresse aus `str(request.base_url)`, also aus
# genau diesem Header — das Opfer bekam eine echte Mail der echten App mit einem gültigen Token
# in einem Link auf den Server des Angreifers (CWE-644). `trusted_redirect_hosts` schützte nur
# `?next=`, nicht diesen Weg; `X-Forwarded-Host` braucht es dafür nicht.
BOESE = "angreifer.example"
ECHT = "https://auth.example.com"


def _mailapp(**cfg):
    post: list = []
    # `base_url` steht jetzt in der Grundausstattung: Seit der Nacharbeit ist sie Pflicht, sobald
    # ein Mail-Weg an ist — eine Instanz ohne sie gibt es nicht mehr (Prüfung dazu weiter unten).
    grund = dict(csrf_enabled=False, magiclink_enabled=True, password_reset_enabled=True,
                 signup_verify_email=True, allow_signup=True, signup_require_email=True,
                 passkey_enabled=False, trusted_redirect_hosts=["nur-das-hier.example"],
                 base_url=ECHT)
    grund.update(cfg)
    auth, app = _app(**grund)
    auth.set_mailer(lambda to, betreff, text, html=None: post.append(text))
    auth.create_user("opfer", password="Geheim12345!", email="opfer@example.com")
    return auth, TestClient(app), post


def _links(post) -> list[str]:
    return re.findall(r"https?://[^\s]+", "\n".join(post))


# Vorbedingung: Ohne diese Prüfung wäre „keine Mail auf dem Angreifer-Host" auch dann grün,
# wenn der Mailer gar nicht verdrahtet ist — der Angriff würde dann nichts belegen.
_a, _c, _post = _mailapp()
_c.post("/auth/forgot", data={"email": "opfer@example.com"})
r.check("Vorbedingung: der Weg funktioniert überhaupt (Mail geht raus)",
        len(_post) == 1 and _links(_post)[0].startswith(ECHT + "/auth/reset"),
        f"{_post!r} — ohne diese Zusage prüft der Angriff unten nichts")

# Der Angriff selbst, an allen drei Stellen, die eine Mail mit Token verschicken.
for pfad, daten, name in (
        ("/auth/forgot", {"email": "opfer@example.com"}, "Reset-Link"),
        ("/auth/magic/request", {"email": "opfer@example.com", "next": "/"}, "Magic-Link"),
        ("/auth/register", {"username": "neu", "password": "Geheim12345!",
                            "email": "neu@example.com"}, "Bestätigungslink")):
    auth_x, c_x, post_x = _mailapp()
    antwort_x = c_x.post(pfad, data=daten, headers={"host": BOESE})
    r.check(f"{name}: gefälschter Host-Header erzeugt keine Mail auf {BOESE}",
            not any(BOESE in u for u in _links(post_x)),
            f"{_links(post_x)!r} — das Opfer bekäme ein gültiges Token auf {BOESE}")
    r.check(f"...und der Weg bleibt heil (Mail auf {ECHT}, HTTP {antwort_x.status_code})",
            len(post_x) == 1 and _links(post_x)[0].startswith(ECHT),
            f"{_links(post_x)!r} — base_url gewinnt, der Header zählt nicht mit")

# ── Nacharbeit N1: der Host-Header darf nicht einmal unter MEHREREN eigenen Hosts wählen ──
# Befund A-umgehung-4: `base_url` war nur eine Warnung. Blieb sie leer und standen — beim
# Forward-Auth/SSO der Normalfall — mehrere Namen in `trusted_redirect_hosts`, dann galt der
# Laufzeit-Prüfung JEDER davon: Der Angreifer stieß „Passwort vergessen" für ein fremdes Postfach
# an und setzte `Host:` auf einen anderen mitvertrauten Host. Ist der schwächer (fremdes Team,
# offener Redirect, mitgeschnittenes Access-Log), leckt der Reset-Token dort. Jetzt ist `base_url`
# Pflicht und gewinnt immer — der Header hat keine Stimme mehr.
auth_m, c_m, post_m = _mailapp(trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"])
c_m.post("/auth/forgot", data={"email": "opfer@example.com"},
         headers={"host": "app-b.example.com"})
r.check("zweiter mitvertrauter Host im Header gewinnt nicht gegen base_url",
        len(post_m) == 1 and _links(post_m)[0].startswith(ECHT + "/auth/reset"),
        f"{_links(post_m)!r} — der Reset-Token ginge auf den vom Angreifer gewählten Host")

# Befund A-regression-1/A-vollstaendigkeit-3: Ohne Basis rendeten `/auth/forgot` und
# `/auth/magic/request` weiter die ERFOLGSSEITE — HTTP 200, „Mail ist unterwegs", keine Mail.
# Sichtbar war der Totalausfall nur in einer Logzeile. Zwei Schlösser dagegen:
#
# (1) Die Konfigurationsprüfung lässt diesen Aufbau nicht mehr entstehen (Fehler, nicht Warnung).
from tinysesam import konfigpruefung as _kp  # noqa: E402

for _feld, _zusatz in (("magiclink_enabled", {}),
                       ("password_reset_enabled", {"magiclink_enabled": True}),
                       ("signup_verify_email", {"signup_require_email": True}),
                       ("oidc_enabled", {"oidc_issuer": "https://idp.example.com",
                                         "oidc_client_id": "c", "oidc_client_secret": "s"}),
                       ("saml_enabled", {"saml_idp_sso_url": "https://idp.example.com/sso",
                                         "saml_idp_x509cert": "PEM"})):
    _f, _w = _kp.pruefe(TinySesamConfig(db_path=":memory:", **{_feld: True}, **_zusatz))
    r.check(f"ohne base_url ist {_feld} ein FEHLER, keine Warnung",
            any("base_url ist leer" in x for x in _f),
            f"nur Warnungen: {[x[:60] for x in _w]!r} — eine Warnung startet durch")
_f_hosts, _w_hosts = _kp.pruefe(TinySesamConfig(
    db_path=":memory:", magiclink_enabled=True,
    trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"]))
r.check("trusted_redirect_hosts ersetzt base_url NICHT",
        any("base_url ist leer" in x for x in _f_hosts),
        "mit mehreren mitvertrauten Hosts wählt sonst der Header aus (A-umgehung-4)")
_gebaut_ohne, _text_ohne = _baut(magiclink_enabled=True, password_reset_enabled=True)
r.check("...und der Konstruktor bricht damit ab (ConfigError statt stillem Betrieb)",
        not _gebaut_ohne and "base_url" in _text_ohne, f"gebaut={_gebaut_ohne}")
r.check("...die Meldung sagt, was einzutragen ist",
        "base_url=" in _text_ohne, f"nur Diagnose, keine Abhilfe: {_text_ohne[:160]!r}")
# Gegenprobe: Der Wächter darf nicht jeden Aufbau treffen. Nur Passwort/PIN braucht keine Basis.
_f_pw, _w_pw = _kp.pruefe(TinySesamConfig(db_path=":memory:"))
r.check("ohne linkbauende Funktion verlangt niemand ein base_url",
        not any("base_url" in x for x in _f_pw + _w_pw), f"{(_f_pw, _w_pw)!r}")
# Forward-Auth allein bleibt eine Warnung: Die Umleitung bleibt ohne Basis relativ und trifft
# denselben Browser, es geht nichts an Dritte hinaus.
_f_fa, _w_fa = _kp.pruefe(TinySesamConfig(db_path=":memory:", forward_auth_enabled=True))
r.check("forward_auth allein bleibt eine Warnung (die Umleitung bleibt relativ)",
        not any("base_url" in x for x in _f_fa) and any("base_url" in x for x in _w_fa),
        f"Fehler={[x[:50] for x in _f_fa]!r} Warnungen={[x[:50] for x in _w_fa]!r}")

# (2) Zweites Schloss für die Config, die NACH dem Konstruktor geändert wurde (sie wird zur
# Request-Zeit gelesen): kein stiller Erfolg, sondern ein Abbruch mit klarer Meldung — seit der
# Nacharbeit zu „base_url nach dem Konstruktor geleert" als HTTP 503 aus der Route
# (`router._mail_basis`), nicht mehr als ungefangener ConfigError.
from tinysesam import ConfigError as _CfgErr  # noqa: E402

for _pfad, _daten, _name in (("/auth/forgot", {"email": "opfer@example.com"}, "Passwort vergessen"),
                             ("/auth/magic/request", {"email": "opfer@example.com", "next": "/"},
                              "Magic-Link")):
    auth_l, c_l, post_l = _mailapp()
    auth_l.cfg.base_url = ""            # Mutationsprobe: die Basis fällt zur Laufzeit weg
    try:
        _antwort_l = c_l.post(_pfad, data=_daten)
        _ergebnis = f"HTTP {_antwort_l.status_code}, Erfolgsseite: {'unterwegs' in _antwort_l.text}"
        _hart = _antwort_l.status_code == 503 and "unterwegs" not in _antwort_l.text
    except _CfgErr as _e:
        _ergebnis, _hart = f"ungefangen: {str(_e)[:60]}", False
    r.check(f"{_name} ohne Basis: 503 statt „Mail ist unterwegs\" (und statt eines 500)",
            _hart and not post_l,
            f"{_ergebnis} — 200 mit Erfolgsseite verdeckt den Totalausfall (A-regression-1)")

# Und was der Betreiber dabei WIRKLICH zu sehen bekommt — im Betrieb, ohne TestClient, der eine
# Ausnahme durchreicht. Bis zur Nacharbeit fing keine Route den `ConfigError`, und der ASGI-Server
# machte daraus einen HTTP 500 (so stand es im CHANGELOG). Jetzt fängt `_mail_basis()` ihn und
# antwortet 503: Der Dienst ist so nicht einsatzbereit, und das sagt die Antwort auch. Gemessen
# wird beides: kein stiller Erfolg, und genau 503 — nicht 500, nicht 200.
# (Mutationsprobe: `_mail_basis` durch `auth.require_public_base(request)` ersetzen → 500, rot.)
auth_500, app_500 = _app(csrf_enabled=False, magiclink_enabled=True, password_reset_enabled=True,
                         passkey_enabled=False, base_url=ECHT)
_post_500: list = []
auth_500.set_mailer(lambda to, betreff, text, html=None: _post_500.append(text))
auth_500.create_user("opfer", password="Geheim12345!", email="opfer@example.com")
auth_500.cfg.base_url = ""              # die Lage, für die das zweite Schloss gebaut ist
_c500 = TestClient(app_500, raise_server_exceptions=False)
_antwort_500 = _c500.post("/auth/forgot", data={"email": "opfer@example.com"})
r.check("kein stiller Erfolg: ohne Basis meldet /auth/forgot nicht „Mail ist unterwegs\"",
        _antwort_500.status_code != 200 and not _post_500,
        f"HTTP {_antwort_500.status_code}, Mails={len(_post_500)} — dieselbe Antwort verhindert "
        "die Benutzer-Enumeration und verdeckte deshalb den Totalausfall (A-regression-1)")
r.check("...sondern HTTP 503 aus der Route, kein ungefangener 500",
        _antwort_500.status_code == 503,
        f"HTTP {_antwort_500.status_code} — 500 heisst: der ConfigError läuft wieder ungefangen "
        "bis zum ASGI-Server (CHANGELOG-Satz dazu mitändern)")
# Einladung aus dem Panel: dieselbe Klasse, derselbe Riegel.
auth_inv, app_inv = _app(csrf_enabled=False, magiclink_enabled=True, passkey_enabled=False,
                         base_url=ECHT)
auth_inv.set_mailer(lambda *a, **k: None)
auth_inv.ensure_admin("chefin", "Geheim12345!")
_ci = TestClient(app_inv, raise_server_exceptions=False)
_ci.post("/auth/login", data={"username": "chefin", "password": "Geheim12345!"})
auth_inv.cfg.base_url = ""
_inv = _ci.post("/auth/admin/api/invite", json={"email": "gast@example.com"})
r.check("Admin-Einladung ohne Basis: 503, kein 500 und kein Link",
        _inv.status_code == 503 and "claim" not in _inv.text and "/auth/" not in _inv.text,
        f"HTTP {_inv.status_code}: {_inv.text[:120]!r}")

# Befund A-regression-4: Dieselben Stellen antworteten sonst mit 500 mitten im Anmeldeversuch —
# `/auth/oidc/start` ist der Einstieg, auf den ein Gateway jeden Besucher schickt. Jetzt steht
# der Abbruch beim Aufbau, also bevor ein Nutzer klickt.
for _name, _an in (("OIDC", dict(oidc_enabled=True, oidc_issuer="https://idp.example.com",
                                 oidc_client_id="c", oidc_client_secret="s")),
                   ("SAML", dict(saml_enabled=True, saml_idp_sso_url="https://idp.example.com/sso",
                                 saml_idp_x509cert="PEM")),
                   ("Einladung/Magic", dict(magiclink_enabled=True))):
    _gebaut, _text = _baut(**_an)
    r.check(f"{_name} ohne base_url: Abbruch beim Aufbau, kein 500 zur Laufzeit",
            not _gebaut and "base_url" in _text, f"gebaut={_gebaut}: {_text[:90]!r}")

# Der legitime Weg bleibt: mit zugesagter base_url geht die Mail hinaus, und der gefälschte
# Host steht nicht drin. Ohne diese Prüfung wäre der Fix „nie wieder eine Mail" auch grün.
auth_ok, c_ok, post_ok = _mailapp(base_url=ECHT)
c_ok.post("/auth/forgot", data={"email": "opfer@example.com"}, headers={"host": BOESE})
r.check("legitimer Weg: base_url gesetzt → Mail geht raus und trägt die echte Adresse",
        len(post_ok) == 1 and _links(post_ok)[0].startswith(ECHT + "/auth/reset"),
        f"{_links(post_ok)!r}")
r.check("und der gefälschte Host taucht nirgends auf", BOESE not in "\n".join(post_ok),
        f"{post_ok!r}")

# Der Einladungslink des Admin-Panels geht ebenfalls per Mail an einen Dritten und trägt ein
# Token — er kam aus derselben Zeile und blieb in einer früheren Runde beim Flicken liegen.
auth_inv, app_inv = _app(csrf_enabled=False, magiclink_enabled=True, passkey_enabled=False,
                         base_url=ECHT)
auth_inv.set_mailer(lambda *a, **k: None)
auth_inv.create_user("chef", password="Geheim12345!", is_admin=True)
with TestClient(app_inv) as c_inv:
    c_inv.cookies.set(auth_inv.cfg.session_cookie,
                      auth_inv.store.create_session(auth_inv.store.get_user_by_name("chef")["id"],
                                                    3600, True, "password"))
    einladung = c_inv.post("/auth/admin/api/invite", json={"email": "gast@example.com"},
                           headers={"host": BOESE})
r.check("Admin-Einladung: der Link kommt aus base_url, nicht aus dem Host-Header",
        einladung.status_code == 200 and BOESE not in einladung.text
        and ECHT + "/auth/invite/" in einladung.text,
        f"HTTP {einladung.status_code}: {einladung.text[:120]!r}")

# Die Regel selbst, direkt geprüft — sie entscheidet auch für OIDC-Redirect-URI, SAML-Metadaten
# und die Forward-Auth-Umleitung, die alle über `public_base()` gehen.
from tinysesam import security as _sec  # noqa: E402

r.check("fremder Host gilt nicht als eigener", _sec.eigener_host(BOESE, []) is False)
r.check("Host aus trusted_redirect_hosts gilt", _sec.eigener_host("a.example.com", ["a.example.com"]))
r.check("Loopback gilt (Link nützt nur dem Empfänger selbst)",
        _sec.eigener_host("127.0.0.1", []) and _sec.eigener_host("::1", []))
r.check("Benutzerangabe im Host täuscht die Prüfung nicht",
        _sec.sichere_basis("https://a.example.com@" + BOESE, ["a.example.com"]) == "",
        "urlsplit liest hier den Host hinter dem @ — die Prüfung muss genau den sehen")
r.check("und die geprüfte Basis trägt keine Benutzerangabe weiter",
        _sec.sichere_basis("https://wer@a.example.com:8443", ["a.example.com"])
        == "https://a.example.com:8443")
auth_pb, _app_pb = _app(passkey_enabled=False)
r.check("public_base() liefert leer statt zu raten (fail closed)",
        auth_pb.public_base(kandidat="https://" + BOESE) == "")
try:
    auth_pb.require_public_base(kandidat="https://" + BOESE)
    _pb_hart = False
except _CfgErr:
    _pb_hart = True
r.check("require_public_base() wirft statt zu raten",
        _pb_hart, "wer eine Basis BRAUCHT, darf keinen leeren String bekommen")

# Befund A-regression-12: Der `root_path` des Servers fiel weg — eine unter einem Unterpfad
# montierte App verschickte Mail-Links ohne Präfix, also 404 statt Reset-Formular.
_auth_pfad = TinySesam(TinySesamConfig(db_path=":memory:",
                                      base_url="https://app.example.com/sso/"))
r.check("der Unterpfad (root_path) kommt aus base_url mit",
        _auth_pfad.public_base() == "https://app.example.com/sso",
        f"{_auth_pfad.public_base()!r} — Mail-Links ohne Präfix landen im 404")
r.check("...und auch aus einer abgeleiteten Basis",
        _sec.sichere_basis("https://a.example.com/sso/", ["a.example.com"])
        == "https://a.example.com/sso",
        "bis 0.18.x warf sichere_basis den Pfad weg")
r.check("...aber nichts, was wir nicht sauber zusammensetzen können (fail closed)",
        all(_sec.sichere_basis("https://a.example.com" + _p, ["a.example.com"]) == ""
            for _p in ("/../etc", "/sso/../x", "/a//b", "/s so", "/a%2fb")),
        "ein halb geratenes Präfix ginge in jede ausgehende Mail")

# Zuletzt: Die Konfigurationsprüfung schwieg zu `base_url` komplett — wer die Lücke offen ließ,
# erfuhr es nirgends.
from tinysesam import konfigpruefung as _kp  # noqa: E402

_fehler, _warn = _kp.pruefe(TinySesamConfig(password_reset_enabled=True))
r.check("konfigpruefung nennt das fehlende base_url",
        any("base_url ist leer" in f for f in _fehler), f"{_fehler!r}")
_fehler2, _warn2 = _kp.pruefe(auth_ok.cfg)
r.check("mit gesetztem base_url schweigt sie dazu",
        not any("base_url ist leer" in m for m in _fehler2 + _warn2), f"{_fehler2!r} {_warn2!r}")

# Gemessen wird die Warnung für JEDEN Schalter, der eine absolute Adresse baut — nicht nur für
# die Mail-Wege. Vorher deckte die Suite drei der sechs Einträge ab: `BRAUCHT_BASE_URL` ließ
# sich um `oidc_enabled`, `saml_enabled` und `forward_auth_enabled` kürzen, ohne dass eine
# einzige Prüfung rot wurde (Mutationsprobe N4, volle Suite 46/46 grün).
#
# Die sechs Schalter stehen deshalb AUSGESCHRIEBEN, nicht als Schleife über die Tabelle selbst:
# eine Schleife über `BRAUCHT_BASE_URL` prüfte nur die Einträge, die noch drin sind — wer einen
# entfernt, nähme sich damit auch die Prüfung weg. (Genau das fiel beim Nachstellen der
# Mutationsprobe auf.) Gefragt wird eine nackte Config, keine Instanz: `pruefe` liest nur
# Felder, und so braucht die Zeile weder [oidc] noch [saml].
#
# Seit der Nacharbeit N1 ist die Meldung nach Schwere getrennt: Die fünf Wege, die eine absolute
# Adresse in FREMDE Hand geben (Mail, IdP), sind ein **Fehler** — der Aufbau scheitert, weil eine
# Warnung durchstartet und `/auth/forgot` sonst weiter die Erfolgsseite ohne Mail rendert.
# Forward-Auth bleibt eine **Warnung**: Die Umleitung bleibt ohne Basis relativ, trifft denselben
# Browser und gibt nichts an Dritte. Beide Tabellen werden hier gemessen, jede in ihrer Schwere.
_BRAUCHT_BASIS = ("magiclink_enabled", "password_reset_enabled", "signup_verify_email",
                  "oidc_enabled", "saml_enabled")
_EMPFIEHLT_BASIS = ("forward_auth_enabled",)
r.check("die Tabelle nennt alle sechs Funktionen, die absolute Adressen bauen",
        set(_BRAUCHT_BASIS) <= set(_kp.BRAUCHT_BASE_URL)
        and set(_EMPFIEHLT_BASIS) <= set(_kp.BASE_URL_EMPFOHLEN),
        f"nicht genannt: {sorted((set(_BRAUCHT_BASIS) - set(_kp.BRAUCHT_BASE_URL)) | (set(_EMPFIEHLT_BASIS) - set(_kp.BASE_URL_EMPFOHLEN)))}")
for _feld in _BRAUCHT_BASIS:
    _f3, _w3 = _kp.pruefe(TinySesamConfig(**{_feld: True}))
    r.check(f"konfigpruefung meldet {_feld} ohne base_url als FEHLER",
            any("base_url ist leer" in f for f in _f3),
            f"{_f3!r} — dieser Schalter gibt eine absolute Adresse aus der Hand, sagt es aber niemandem")
for _feld in _EMPFIEHLT_BASIS:
    _f3, _w3 = _kp.pruefe(TinySesamConfig(**{_feld: True}))
    r.check(f"konfigpruefung warnt bei {_feld} ohne base_url (kein Fehler)",
            any("base_url ist leer" in w for w in _w3)
            and not any("base_url ist leer" in f for f in _f3),
            f"F={_f3!r} W={_w3!r} — die Umleitung bleibt relativ, das darf den Start nicht verweigern")

# ── R4-01, die sechs Stellen ohne Mail: OIDC, SAML, Forward-Auth ───────────────
# Dieselbe Regel, andere Wege. Getestet waren bis hierher nur die vier Mail-Wege; die übrigen
# Stellen verhielten sich richtig, aber ungemessen — jede ließ sich auf die alte Form
# `cfg.base_url or <aus dem Request>` zurückbauen, ohne dass die volle Suite rot wurde
# (Mutationsproben N5–N8, je 46/46 grün). Genau hier arbeitet F-16 weiter, das die
# SAML-SP-Identität betrifft: ohne diese Prüfungen reißt ein Umbau R4-01 still wieder auf.
from urllib.parse import unquote, urlsplit  # noqa: E402

_OIDC_META = {
    "issuer": "https://idp.example.invalid",
    "authorization_endpoint": "https://idp.example.invalid/authorize",
    "token_endpoint": "https://idp.example.invalid/token",
    "jwks_uri": "https://idp.example.invalid/jwks",
    "end_session_endpoint": "https://idp.example.invalid/logout",
}


def _oidc_app(**cfg):
    cfg.setdefault("base_url", ECHT)
    auth_x, app_x = _app(oidc_enabled=True, oidc_issuer="https://idp.example.invalid",
                         oidc_client_id="probe", oidc_client_secret="geheim",
                         csrf_enabled=False, passkey_enabled=False, **cfg)
    auth_x.oidc._meta = dict(_OIDC_META)   # kein Netz nötig: geprüft wird die Basis, nicht Discovery
    return auth_x, app_x


def _oidc_app_ohne_basis(**cfg):
    """Dieselbe App, aber mit leerer Basis zur REQUEST-Zeit.

    Seit N1 verweigert der Konstruktor `oidc_enabled` ohne `base_url` rundheraus — diese Lage ist
    also gar nicht mehr aufzubauen. Gemessen wird deshalb das zweite Schloss, das genau dafür da
    ist: eine Config, die nach dem Konstruktor geändert wurde (sie wird zur Request-Zeit
    gelesen). Ohne dieses Schloss fiele der Router auf den Host-Header zurück.
    """
    auth_x, app_x = _oidc_app(**cfg)
    auth_x.cfg.base_url = ""
    return auth_x, app_x


# (1) OIDC-Redirect-URI. Sie entscheidet, wohin der IdP den Autorisierungs-Code schickt — aus dem
# Host-Header abgeleitet würde ein IdP mit locker gepflegten Redirect-URIs den Code an den Host
# des Angreifers ausliefern.
def _bricht_ab(ruf):
    """(brach mit ConfigError ab, Text der Antwort bzw. der Ausnahme).

    Seit N1 werfen diese Wege `ConfigError` statt `HTTPException(500)`: Ein Serverfehler mitten
    im Anmeldeversuch war der falsche Ort für ein Problem, das schon beim Aufbau feststand.
    Gemessen wird deshalb der Abbruch, nicht mehr eine Statuszeile — und in beiden Fällen, dass
    der fremde Host nirgends durchschlägt.
    """
    try:
        antwort = ruf()
    except _CfgErr as e:
        return True, str(e)
    return False, getattr(antwort, "text", "") + str(getattr(antwort, "headers", ""))


_a_oi, _app_oi = _oidc_app_ohne_basis()
with TestClient(_app_oi) as _c:
    _oi_ab, _oi_text = _bricht_ab(
        lambda: _c.get("/auth/oidc/start", headers={"host": BOESE}, follow_redirects=False))
r.check("OIDC-Start: gefälschter Host baut keine Redirect-URI (fail closed)",
        _oi_ab and BOESE not in unquote(_oi_text),
        f"abgebrochen={_oi_ab}: {_oi_text[:160]!r}")

_a_oi2, _app_oi2 = _oidc_app(base_url=ECHT)
with TestClient(_app_oi2) as _c:
    _start_gut = _c.get("/auth/oidc/start", headers={"host": BOESE}, follow_redirects=False)
_ziel_gut = unquote(_start_gut.headers.get("location", ""))
r.check("...und mit base_url läuft der Flow weiter, auf der eigenen Adresse",
        _start_gut.status_code == 303 and ECHT + "/auth/oidc/callback" in _ziel_gut
        and BOESE not in _ziel_gut,
        f"HTTP {_start_gut.status_code}: {_ziel_gut[:160]!r} — sonst prüft die Zeile darüber nur, "
        "dass der Start überhaupt kaputt ist")

# (2) OIDC-Post-Logout. Der `post_logout_redirect_uri` geht an den IdP; aus dem Host-Header
# abgeleitet schickt der IdP das Opfer nach dem Abmelden auf den Server des Angreifers.
def _abmelden(auth_x, app_x):
    uid = auth_x.create_user("wer", password="Geheim12345!")
    tok = auth_x.store.create_session(uid, 3600, True, "oidc")
    with TestClient(app_x) as c:
        c.cookies.set(auth_x.cfg.session_cookie, tok)
        return c.get("/auth/logout", headers={"host": BOESE}, follow_redirects=False)


_a_pl, _app_pl = _oidc_app_ohne_basis(oidc_rp_logout=True)
_logout_boese = _abmelden(_a_pl, _app_pl)
_loc_boese = unquote(_logout_boese.headers.get("location", ""))
r.check("OIDC-Logout: kein post_logout_redirect_uri aus dem Host-Header",
        BOESE not in _loc_boese and _loc_boese == _a_pl.cfg.logout_redirect,
        f"{_loc_boese!r} — der IdP schickte das Opfer danach zum Angreifer")

_a_pl2, _app_pl2 = _oidc_app(oidc_rp_logout=True, base_url=ECHT)
_loc_gut = unquote(_abmelden(_a_pl2, _app_pl2).headers.get("location", ""))
r.check("...und mit base_url meldet der Provider-Logout weiter ab (der Weg lebt)",
        _loc_gut.startswith("https://idp.example.invalid/logout")
        and ECHT + _a_pl2.cfg.logout_redirect in _loc_gut and BOESE not in _loc_gut,
        f"{_loc_gut!r}")


# (3) SAML: Entity-ID und ACS-URL. Beides ist die IDENTITÄT des SP — ein fremder Name darin
# wandert in den AuthnRequest und in die Metadaten, die der Betreiber beim IdP hinterlegt.
# Die Attrappe steht für den echten Client: geprüft wird die Basis, die der Router ihm gibt,
# nicht die Signaturarbeit von python3-saml. So braucht diese Zeile das Extra [saml] nicht —
# ein Überspringen wäre hier kein Grün.
class _SamlAttrappe:
    def login_url(self, req, base, return_to="/"):
        return f"https://idp.example.invalid/sso?sp={base}&RelayState={return_to}", "rid-1"

    def process(self, req, base, request_id=""):
        return None      # „Assertion abgelehnt" → 400; ein 500 hieße: es gab gar keine Basis

    def metadata(self, base):
        return f'<EntityDescriptor entityID="{base}/auth/saml/metadata"/>'


def _saml_app(**cfg):
    tmp = tempfile.mkdtemp()
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False, csrf_enabled=False,
                 passkey_enabled=False)
    grund.update(cfg)
    auth_x = TinySesam(TinySesamConfig(**grund))
    auth_x.saml = _SamlAttrappe()    # VOR router(): die SAML-Routen hängen an auth.saml
    app_x = FastAPI()
    app_x.include_router(auth_x.router())
    return auth_x, app_x


_a_sa, _app_sa = _saml_app()
with TestClient(_app_sa) as _c:
    _md_ab, _md_text = _bricht_ab(lambda: _c.get("/auth/saml/metadata", headers={"host": BOESE}))
    _lg_ab, _lg_text = _bricht_ab(
        lambda: _c.get("/auth/saml/login", headers={"host": BOESE}, follow_redirects=False))
    _acs_ab, _ = _bricht_ab(
        lambda: _c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, headers={"host": BOESE}))
r.check("SAML-Metadaten: keine Entity-ID aus dem Host-Header",
        _md_ab and BOESE not in _md_text, f"abgebrochen={_md_ab}: {_md_text[:160]!r}")
r.check("SAML-Login: kein AuthnRequest mit fremder SP-Adresse",
        _lg_ab and BOESE not in unquote(_lg_text),
        f"abgebrochen={_lg_ab}: {_lg_text[:160]!r}")
r.check("SAML-ACS: bricht ab, bevor eine Assertion gegen eine fremde ACS-URL geprüft wird",
        _acs_ab, "die Assertion wäre gegen eine fremde ACS-URL geprüft worden")

_a_sa2, _app_sa2 = _saml_app(base_url=ECHT)
with TestClient(_app_sa2) as _c:
    _md_gut = _c.get("/auth/saml/metadata", headers={"host": BOESE})
    _lg_gut = _c.get("/auth/saml/login", headers={"host": BOESE}, follow_redirects=False)
    _acs_gut = _c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, headers={"host": BOESE})
r.check("...und mit base_url trägt SAML die eigene Adresse (Metadaten, Login, ACS leben)",
        _md_gut.status_code == 200 and f'entityID="{ECHT}/auth/saml/metadata"' in _md_gut.text
        and _lg_gut.status_code == 303 and f"sp={ECHT}" in unquote(_lg_gut.headers["location"])
        and _acs_gut.status_code == 400 and BOESE not in _md_gut.text,
        f"Metadaten HTTP {_md_gut.status_code}: {_md_gut.text[:90]!r}; Login HTTP "
        f"{_lg_gut.status_code}; ACS HTTP {_acs_gut.status_code} (400 = Basis stand, Assertion "
        "abgelehnt; 500 = keine Basis)")

# (4) Forward-Auth-Umleitung. Der Proxy schickt jeden nicht angemeldeten Besucher auf die
# Adresse aus `X-TinySesam-Location` — stünde dort ein fremder Host, führte der Proxy das Opfer
# selbst auf die Anmeldeseite des Angreifers. Geprüft wird der HOST der Umleitung: das `next=`
# trägt die angefragte URL und darf das auch, `safe_next` verwirft sie später.
_a_fa, _app_fa = _app(forward_auth_enabled=True, csrf_enabled=False, passkey_enabled=False,
                      trusted_redirect_hosts=["app.example.com"])
with TestClient(_app_fa) as _c:
    _fa_boese = _c.get("/auth/forward", headers={"host": BOESE, "x-forwarded-host": BOESE,
                                                 "x-forwarded-proto": "https",
                                                 "x-forwarded-uri": "/geheim"})
    _fa_gut = _c.get("/auth/forward", headers={"host": "app.example.com",
                                               "x-forwarded-host": "app.example.com",
                                               "x-forwarded-proto": "https",
                                               "x-forwarded-uri": "/geheim"})
_loc_fa = _fa_boese.headers.get("X-TinySesam-Location", "")
r.check("Forward-Auth: die 401-Umleitung zeigt auf keinen fremden Host",
        _fa_boese.status_code == 401 and not (urlsplit(_loc_fa).hostname or "")
        and _loc_fa.startswith(_a_fa.cfg.login_path + "?next="),
        f"HTTP {_fa_boese.status_code}: {_loc_fa[:140]!r} — der Proxy selbst führte das Opfer hin")
_loc_fa_gut = _fa_gut.headers.get("X-TinySesam-Location", "")
r.check("...und auf einem Host aus trusted_redirect_hosts bleibt sie absolut (Cookie-Host)",
        _fa_gut.status_code == 401
        and _loc_fa_gut.startswith("https://app.example.com" + _a_fa.cfg.login_path),
        f"HTTP {_fa_gut.status_code}: {_loc_fa_gut[:140]!r}")

# ── Dieselbe EINE Regel für die dokumentierten Methoden, nicht nur für die Routen ───
# `public_base()` sass nur in den Routen. Eine App mit eigenem „Passwort vergessen"-Formular —
# der in beiden READMEs und in API.md gezeigte Weg — rief `send_password_reset(mail, basis)`
# selbst auf und war mit `str(request.base_url)` weiter voll angreifbar, während ihr die
# eingebaute Route längst weggebrochen war. Die Prüfung sitzt jetzt in `magic_url()`, wo alle
# vier Mail-Wege zusammenlaufen, und zusätzlich vor der Token-Vergabe in jedem Absender.
#
# Gemessen wird die REGEL, nicht ihr Mechanismus: Steht `base_url`, gewinnt sie — auch gegen
# einen zweiten mitvertrauten Namen. Genau das war Befund B-umgehung-3: Hier entschied noch der
# übergebene Host, solange er in `trusted_redirect_hosts` stand. Der `Host`-Header wählte damit
# weiter aus, welcher der eigenen Namen in den Reset-Link kommt — der Kern von R4-01, eine Ebene
# tiefer. Ohne `base_url` — der einzige Aufbau, in dem überhaupt abgeleitet wird — bleibt es
# beim harten `ConfigError`.
_a_api, _app_api = _app(magiclink_enabled=True, password_reset_enabled=True, passkey_enabled=False,
                        base_url=ECHT,
                        trusted_redirect_hosts=["auth.example.com", "app-b.example.com"])
_mails_api: list = []
_a_api.set_mailer(lambda to, betreff, text, html=None: _mails_api.append(text))
_a_api.create_user("opfer", password="Geheim12345!", email="opfer@example.com")
# Diese Runde schickt ein Dutzend Mails an dieselbe Adresse; gemessen wird die Basis, nicht die
# Drossel je Zieladresse (R4-04, eigener Test in test_magic.py) — die bekommt hier Luft.
_a_api.set_security("mail_per_address_max", 100)


def _tokenzeilen(auth_x) -> int:
    return auth_x.store._exec("SELECT COUNT(*) FROM magic_token").fetchone()[0]


def _wege(auth_x, basis):
    """Die fünf dokumentierten Wege, alle mit DERSELBEN übergebenen Basis."""
    return (
        ("magic_url", lambda: auth_x.magic_url("rohtoken", basis, "reset_password")),
        ("send_password_reset", lambda: auth_x.send_password_reset("opfer@example.com", basis)),
        ("send_login_link", lambda: auth_x.send_login_link("opfer@example.com", basis)),
        ("send_verify_email", lambda: auth_x.send_verify_email(1, "opfer@example.com", basis)),
        ("create_invite", lambda: auth_x.create_invite("gast@example.com", basis)),
    )


def _spur(erg, mails) -> str:
    """Alles, was der Aufruf nach aussen gegeben hat: Rückgabe plus verschickte Mailtexte."""
    return repr(erg) + " " + " ".join(mails)


for _fremd, _was in (("https://" + BOESE, "einen fremden Host"),
                     ("https://app-b.example.com", "einen ZWEITEN eigenen Namen")):
    for _name, _ruf in _wege(_a_api, _fremd):
        _mails_api.clear()
        try:                            # ein ConfigError wäre auch hier ein Befund, kein Abbruch
            _s = _spur(_ruf(), _mails_api)
        except ConfigError as e:
            _s = f"ConfigError: {e}"[:140]
        r.check(f"{_name}: base_url gewinnt gegen {_was}",
                (urlsplit(_fremd).hostname or "") not in _s and ECHT in _s,
                f"{_s[:140]!r} — sonst wählt der Host-Header aus, was in den Link kommt")

# Ohne `base_url` bleibt es beim harten Abbruch: kein Link, keine Mail, kein Token. Diesen Aufbau
# lässt `konfigpruefung` als einzigen ohne `base_url` durch (kein Mail-Schalter an), und genau ihn
# nennt der Befund als Anlass — eine einbettende App mit eigenem Formular.
_a_ohne, _app_ohne = _app(passkey_enabled=False, trusted_redirect_hosts=["auth.example.com"])
_mails_ohne: list = []
_a_ohne.set_mailer(lambda to, betreff, text, html=None: _mails_ohne.append(text))
_a_ohne.create_user("opfer", password="Geheim12345!", email="opfer@example.com")
for _name, _ruf in _wege(_a_ohne, "https://" + BOESE):
    try:
        _abgewiesen, _wie = False, repr(_ruf())
    except ConfigError as e:
        _abgewiesen, _wie = True, str(e)[:60]
    r.check(f"ohne base_url: {_name}(fremde Basis) wird abgewiesen, nicht ausgeliefert",
            _abgewiesen, f"kam durch: {_wie} — die App mit eigenem Formular bleibt angreifbar")

r.check("dabei geht keine Mail hinaus", _mails_ohne == [], f"{_mails_ohne!r}")
r.check("und es bleibt kein unbrauchbarer Token in der Datenbank",
        _tokenzeilen(_a_ohne) == 0,
        f"{_tokenzeilen(_a_ohne)} Zeilen — geprüft wird vor der Token-Vergabe, nicht danach")

# Der legitime Weg der App: die zugesagte Basis. Ohne diese Zusage wäre „nie wieder ein Link"
# auch grün. Der Host der eigenen base_url genügt — ein `http://` aus einem TLS-terminierenden
# Proxy wird dabei auf die konfigurierte Adresse gehoben, statt still unverschlüsselt zu bleiben.
_mails_api.clear()
r.check("legitimer Weg: base_url liefert den Link",
        _a_api.magic_url("rohtoken", ECHT, "reset_password") == ECHT + "/auth/reset?token=rohtoken",
        _a_api.magic_url("rohtoken", ECHT, "reset_password"))
r.check("str(request.base_url) auf dem eigenen Host bleibt benutzbar — und wird nicht http",
        _a_api.magic_url("rohtoken", "http://auth.example.com/", "reset_password")
        == ECHT + "/auth/reset?token=rohtoken",
        _a_api.magic_url("rohtoken", "http://auth.example.com/", "reset_password"))
r.check("und der Absender schickt damit wieder (die Methode lebt)",
        _a_api.send_password_reset("opfer@example.com", ECHT) is True
        and len(_mails_api) == 1 and ECHT + "/auth/reset" in _mails_api[0],
        f"{_mails_api!r}")
r.check("auch ohne base_url trägt der legitime Weg (abgeleitete, belegte Basis)",
        _a_ohne.magic_url("rohtoken", "https://auth.example.com", "reset_password")
        == ECHT + "/auth/reset?token=rohtoken",
        _a_ohne.magic_url("rohtoken", "https://auth.example.com", "reset_password"))

# Befund B-regression-2: Der Pfadanteil stand VIERFACH im verschickten Link. `sichere_basis()`
# gibt ihn seit N1 selbst zurück, `_gepruefte_basis()` hängte ihn trotzdem noch einmal an — und
# weil die vier Absender erst selbst prüfen und danach `magic_url()` ein zweites Mal, wuchs
# `https://portal.example.com/portal` zu `…/portal/portal/portal/portal/auth/reset?token=…`.
# Die Mail ging hinaus, der Empfänger klickte, der Link war 404: kein Fehler, keine Logzeile.
# Deshalb wird GEZÄHLT, nicht `startswith` geprüft — genau das hielt den Befund verborgen.
_UNTER = "https://portal.example.com/portal"
_a_pfad, _app_pfad = _app(passkey_enabled=False, trusted_redirect_hosts=["portal.example.com"])
_mails_pfad: list = []
_a_pfad.set_mailer(lambda to, betreff, text, html=None: _mails_pfad.append(text))
_a_pfad.create_user("opfer", password="Geheim12345!", email="opfer@example.com")
_a_pfad.set_security("mail_per_address_max", 100)   # wie oben: gemessen wird der Pfad, nicht R4-04
def _links(texte) -> list:
    """Alle Adressen auf dem Unterpfad-Host, die ein Aufruf nach aussen gegeben hat."""
    return [g for t in texte for g in re.findall(r"https://portal\.example\.com[^\s'\"]*", t)]


for _name, _ruf in _wege(_a_pfad, _UNTER):
    _mails_pfad.clear()
    _erg = _ruf()
    _gefunden = _links([repr(_erg)] + list(_mails_pfad))
    # Gezählt wird im PFAD, nicht im ganzen String: In "https://portal…" steckt "/portal"
    # schon durch das "//" — eine Zählung darüber hätte auch den Vierfach-Link durchgelassen.
    _zaehl = [urlsplit(u).path.count("/portal") for u in _gefunden]
    r.check(f"{_name}: der Unterpfad steht genau EINMAL im Link",
            bool(_zaehl) and all(z == 1 for z in _zaehl)
            and all(u.startswith(_UNTER + "/auth/") for u in _gefunden),
            f"{_zaehl} Vorkommen in {[u[:90] for u in _gefunden]!r}")
r.check("die Prüfung ist idempotent (zweimal angewandt wächst der Pfad nicht)",
        _a_pfad._gepruefte_basis(_a_pfad._gepruefte_basis(_UNTER)) == _UNTER,
        f"{_a_pfad._gepruefte_basis(_a_pfad._gepruefte_basis(_UNTER))!r} — die vier Absender "
        "prüfen vor der Token-Vergabe, magic_url danach noch einmal")

# Befund B-regression-3: Was eine Montage unter einem Unterpfad WIRKLICH trägt — gemessen an
# einer echten Montage (`FastAPI(root_path="/sso")`), nicht an einer nachgebauten URL. Der
# verschickte Link trägt das Präfix; die eingebauten Seiten tragen es NICHT, ihre Ziele stehen
# wurzel-absolut in `templates.py`. Genau so steht es seit dieser Runde in README, KONFIGURATION
# und CHANGELOG. Dieser Test hält die Doku ehrlich: Wird die Grenze verschoben (backlog/T-15),
# wird er rot — und dann gehört die Einschränkung aus der Doku heraus, nicht der Test weg.
_a_mnt = TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"),
                                   cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
                                   password_reset_enabled=True,
                                   base_url="https://example.com/sso"))
_mails_mnt: list = []
_a_mnt.set_mailer(lambda to, betreff, text, html=None: _mails_mnt.append(text))
_a_mnt.create_user("anna", password="Geheim12345!", email="anna@example.com")
_app_mnt = FastAPI(root_path="/sso")
_app_mnt.include_router(_a_mnt.router())
_c_mnt = TestClient(_app_mnt, root_path="/sso", follow_redirects=False)
_c_mnt.post("/auth/forgot", data={"email": "anna@example.com"}, headers={"accept": "text/html"})
_link_mnt = [w for w in " ".join(_mails_mnt).split() if w.startswith("http")]
r.check("echte Montage unter /sso: der Mail-Link trägt das Präfix genau einmal",
        len(_link_mnt) == 1 and _link_mnt[0].startswith("https://example.com/sso/auth/reset?")
        and urlsplit(_link_mnt[0]).path.count("/sso") == 1,
        f"{_link_mnt!r} — ohne Präfix ist es ein 404, mehrfach auch")
_seite_mnt = _c_mnt.get("/auth/login", headers={"accept": "text/html"}).text
_ziel_mnt = _c_mnt.get("/auth/account", headers={"accept": "text/html"}).headers.get("location", "")
r.check("...die eingebauten Seiten bleiben wurzel-absolut (ausgesprochene Grenze, backlog/T-15)",
        "action='/auth/login'" in _seite_mnt and _ziel_mnt.startswith("/auth/login?next="),
        f"{_ziel_mnt!r} — trägt die Seite jetzt das Präfix, gehört die Einschränkung aus "
        "README/KONFIGURATION/CHANGELOG heraus")

# Und die Regel selbst, mechanisch: Wo `public_base()` eine Basis liefert, liefert
# `_gepruefte_basis()` GENAU dieselbe, und wo sie leer bleibt, wirft die Methode. Zwei Wege,
# ein Ergebnis — sonst sind es wieder zwei Regeln, und die Lücke sitzt im Unterschied.
for _lab, _auth_x in (("mit base_url", _a_api), ("ohne base_url", _a_pfad)):
    for _fall in (ECHT, "http://auth.example.com/", "https://app-b.example.com",
                  "https://" + BOESE, _UNTER, ""):
        _pb = _auth_x.public_base(kandidat=_fall)
        try:
            _gb, _warf = _auth_x._gepruefte_basis(_fall), False
        except ConfigError:
            _gb, _warf = "", True
        r.check(f"eine Regel ({_lab}): public_base == _gepruefte_basis für {_fall!r}",
                _gb == _pb and _warf == (not _pb),
                f"public_base={_pb!r} _gepruefte_basis={_gb!r} warf={_warf}")

# ── Eine fremde Registrierung besetzte die Login-Kennung eines Kontos ────────
# Fund R4-12 (drittes Audit). Die Registrierung prüfte die beiden Namensräume nur GETRENNT:
# `email_taken` gegen users.email, `get_user_by_name` gegen users.username. `find_user` sucht im
# Vorgabe-Modus "both" aber in BEIDEN Spalten und lässt bei einem @ die E-Mail gewinnen. Damit
# besetzte ein Fremder die Kennung eines bestehenden Kontos — der Inhaber (auch ein Admin) bekam
# 401 trotz richtigem Passwort, und /auth/password prüfte fortan ein fremdes Geheimnis.

PW_INHABER, PW_EVE = "Geheim12345!", "Angreifer12345!"


def _anmelden(client, kennung, passwort=PW_INHABER):
    return client.post("/auth/login", data={"username": kennung, "password": passwort, "next": "/"},
                       follow_redirects=False)


# Richtung 1: die E-MAIL des Fremden ist der Benutzername des Inhabers.
auth_n1, app_n1 = _app(allow_signup=True, signup_require_email=True, csrf_enabled=False)
chef1 = auth_n1.create_user("chef@example.com", password=PW_INHABER, is_admin=True)
c_n1 = TestClient(app_n1)
r.check("Vorbedingung: der Inhaber kommt mit seiner Kennung hinein",
        _anmelden(c_n1, "chef@example.com").status_code == 303,
        "ohne diesen Ausgangspunkt sagt der Rest der Prüfung nichts")
c_n1.cookies.clear()

angriff1 = c_n1.post("/auth/register",
                     data={"username": "eve", "password": PW_EVE,
                           "email": "chef@example.com", "next": "/"}, follow_redirects=False)
r.check("eine Registrierung, deren E-MAIL der Benutzername eines Kontos ist, wird abgewiesen",
        angriff1.status_code == 409, f"HTTP {angriff1.status_code} — die Kennung ist vergeben")
r.check("...und legt kein Konto an", auth_n1.store.get_user_by_name("eve") is None,
        "das Konto steht trotz Abweisung in der Datenbank")
r.check("...die Kennung zeigt weiter auf den Inhaber",
        (auth_n1.find_user("chef@example.com") or {}).get("id") == chef1,
        "find_user löst auf ein fremdes Konto auf")
r.check("...und der Inhaber meldet sich weiter an",
        _anmelden(c_n1, "chef@example.com").status_code == 303,
        "ausgesperrt — mit dem richtigen Passwort")

# Richtung 2 (die gefährlichere): der BENUTZERNAME des Fremden ist die E-Mail des Inhabers.
auth_n2, app_n2 = _app(allow_signup=True, signup_require_email=True, csrf_enabled=False)
chef2 = auth_n2.create_user("chef", password=PW_INHABER, email="chef@example.com", is_admin=True)
c_n2 = TestClient(app_n2)
angriff2 = c_n2.post("/auth/register",
                     data={"username": "chef@example.com", "password": PW_EVE,
                           "email": "eve@example.com", "next": "/"}, follow_redirects=False)
r.check("eine Registrierung, deren BENUTZERNAME die E-Mail eines Kontos ist, wird abgewiesen",
        angriff2.status_code == 409, f"HTTP {angriff2.status_code} — die Kennung ist vergeben")
r.check("...und die E-Mail-Kennung zeigt weiter auf den Inhaber",
        (auth_n2.find_user("chef@example.com") or {}).get("id") == chef2,
        "die Kennung wurde übernommen")

# Der legitime Weg bleibt offen — sonst wäre der Wächter nur eine kaputte Registrierung.
frisch = c_n2.post("/auth/register",
                   data={"username": "neu", "password": "Neues12345!",
                         "email": "neu@example.com", "next": "/"}, follow_redirects=False)
r.check("eine Registrierung mit freien Kennungen geht weiterhin durch", frisch.status_code == 303,
        f"HTTP {frisch.status_code}: {frisch.text[:120]}")

# Und dieselbe Zeichenfolge in beiden Spalten DESSELBEN Kontos ist keine Kollision — im
# E-Mail-Modus ist die Adresse der Benutzername, das ist der vorgesehene Weg.
auth_n3, app_n3 = _app(allow_signup=True, signup_require_email=True,
                       login_identifier="email", csrf_enabled=False)
solo = TestClient(app_n3).post("/auth/register",
                               data={"password": "Einzel-Weg-2468!", "email": "solo@example.com",
                                     "next": "/"}, follow_redirects=False)
r.check("im E-Mail-Modus bleibt die Adresse zugleich Benutzername", solo.status_code == 303,
        f"HTTP {solo.status_code}: {solo.text[:120]}")

# Der Wächter sitzt in create_user, nicht nur in der Route: CLI, Einladung und die Anlage aus
# OIDC/LDAP/SAML kommen hier vorbei.
for was, ruf in (("einen Benutzernamen, der fremde E-Mail ist",
                  lambda: auth_n2.create_user("chef@example.com", password=PW_EVE)),
                 ("eine E-Mail, die fremder Benutzername ist",
                  lambda: auth_n2.create_user("zweitkonto", password=PW_EVE, email="chef"))):
    try:
        ruf()
        entstanden = True
    except ConfigError:
        entstanden = False
    r.check(f"create_user nimmt {was} nicht an", not entstanden,
            "das Konto entsteht — dann hilft die Prüfung in der Route allein nichts")

# Auch über das Admin-Panel darf die Kollision nicht entstehen.
c_adm = TestClient(app_n2)
c_adm.cookies.set(auth_n2.cfg.session_cookie,
                  auth_n2.store.create_session(chef2, 3600, True, "password"))
for feld, koerper in (("E-Mail", {"username": "eve2", "email": "chef@example.com"}),
                      ("Benutzername", {"username": "chef@example.com", "email": "e2@example.com"})):
    antwort_adm = c_adm.post("/auth/admin/api/users", json=koerper)
    r.check(f"die Admin-API weist eine vergebene Kennung im Feld {feld} ab",
            antwort_adm.status_code == 409,
            f"HTTP {antwort_adm.status_code}: {antwort_adm.text[:120]}")

# Einladung: Die Adresse kommt dort aus dem Token, nicht aus dem Formular — der Wächter muss
# auch diesen Weg treffen, sonst legt eine Einladung auf eine vergebene Kennung ein Konto an.
# Die Basis muss seit N6 selbst belegt sein (`_gepruefte_basis`) — ein frei erfundener Host
# geht nicht mehr in einen verschickten Link. Hier steht Loopback dafür; geprüft wird ohnehin
# nur der Token, nicht der Link.
_einladung = auth_n2.create_invite("chef@example.com", "http://127.0.0.1:8000")["token"]
antwort_inv = c_n2.post("/auth/register",
                        data={"username": "eve3", "password": PW_EVE, "invite": _einladung,
                              "next": "/"}, follow_redirects=False)
r.check("eine Einladung auf eine vergebene Kennung wird abgewiesen",
        antwort_inv.status_code == 409,
        f"HTTP {antwort_inv.status_code}: {antwort_inv.text[:120]}")
r.check("...und legt kein Konto an", auth_n2.store.get_user_by_name("eve3") is None,
        "das Konto steht trotz Abweisung in der Datenbank")

# Und der Maschinen-Weg: ein Dienstkonto hat keinen Login, sein Name ist aber trotzdem eine
# Kennung im gemeinsamen Raum (`find_user` sucht auch ihn).
try:
    auth_n2.create_service("chef@example.com")
    _dienst_entstand = True
except ConfigError:
    _dienst_entstand = False
r.check("create_service nimmt eine vergebene Kennung nicht an", not _dienst_entstand,
        "das Dienstkonto entsteht — und besetzt die Kennung des Admins")

# Altbestand: in einer Datenbank von VOR dem Fix steht die Kollision schon. Dann darf
# /auth/password wenigstens nicht das Geheimnis des anderen prüfen (Kette R4-12 + R4-10).
auth_alt, app_alt = _app(csrf_enabled=False)
opfer_alt = auth_alt.create_user("chef", password=PW_INHABER, email="chef@example.com")
eve_alt = auth_alt.store.create_user("chef@example.com")      # am Wächter vorbei = Altbestand
auth_alt.set_password(eve_alt, PW_EVE)
r.check("Vorbedingung: die Kennung des Angreifers löst auf das fremde Konto auf",
        (auth_alt.find_user("chef@example.com") or {}).get("id") == opfer_alt,
        "ohne diese Zweideutigkeit prüft der Test nichts")
c_alt = TestClient(app_alt)
c_alt.cookies.set(auth_alt.cfg.session_cookie,
                  auth_alt.store.create_session(eve_alt, 3600, True, "password"))
fremd = c_alt.post("/auth/password", json={"current": PW_INHABER, "new": "Neues12345!"})
r.check("/auth/password nimmt das Passwort eines FREMDEN Kontos nicht an",
        fremd.status_code == 403,
        f"HTTP {fremd.status_code} — die Route ist ein Orakel für fremde Passwörter")
r.check("...und das fremde Passwort gilt unverändert weiter",
        auth_alt.check_password("chef", PW_INHABER) is not None,
        "das Geheimnis des Opfers wurde überschrieben")
eigen = c_alt.post("/auth/password", json={"current": PW_EVE, "new": "Neues12345!"})
r.check("...prüft aber weiterhin das eigene", eigen.status_code == 200,
        f"HTTP {eigen.status_code}: {eigen.text[:120]}")

# Und der Bestand selbst? Die Datenbank kann diese Kollision nicht verhindern: `UNIQUE(username)`
# und `ux_users_email` gelten je SPALTE, es gibt keinen Index über beide Namensräume — und
# `create_user` prüft und INSERTet nicht atomar. Der Wächter kann hier also nur MELDEN, und genau
# das muss er beim Start tun: Ohne Zeile bleibt ein ausgesperrter Inhaber unerklärlich.


def _start_log(db_pfad):
    """Eine Instanz auf dieser Datenbank aufbauen und mitschreiben, was sie beim Start sagt."""
    puffer = io.StringIO()
    haken = logging.StreamHandler(puffer)
    seclog.addHandler(haken)
    try:
        TinySesam(TinySesamConfig(db_path=db_pfad, cookie_secure=False))
    finally:
        seclog.removeHandler(haken)
    return puffer.getvalue()


r.check("Vorbedingung: die Kreuz-Kollision steht wirklich in der Datenbank",
        len(auth_alt.store.kennungs_kollisionen()) == 1,
        f"{[dict(z) for z in auth_alt.store.kennungs_kollisionen()]} — dann misst der Test nichts")
_text_k = _start_log(auth_alt.cfg.db_path)
r.check("der Start meldet eine Kennungs-Kollision im Bestand", "Kennungs-Kollision" in _text_k,
        f"stumm: {_text_k[:120]!r} — niemand erfährt, warum ein Konto nicht mehr hereinkommt")
r.check("...und nennt beide beteiligten Konten",
        f"user_id={eve_alt}" in _text_k and f"user_id={opfer_alt}" in _text_k,
        f"ohne IDs ist die Meldung nicht abarbeitbar: {_text_k[:200]!r}")
# B-regression-7: Bis zu dieser Runde riet dieselbe Meldung „Eine der beiden Kennungen ändern
# (Admin-Panel oder CLI)" — und keins von beiden kann das. Die Admin-API kennt Anlegen, Sperren,
# Rollen, Passwort und Keys, aber keine Route zum Umbenennen; das CLI legt überhaupt keine Konten
# an. Der Betreiber, dem der Start gerade eine Kollision gemeldet hat, lief damit gegen zwei
# Türen, die es nicht gibt. Gemessen wird deshalb nicht der Wortlaut, sondern dass die genannten
# Wege existieren — und dass für den Benutzernamen wirklich nur die Datenbank bleibt.
r.check("...und nennt Wege, die es wirklich gibt (store.set_email, sonst die Datenbank)",
        "store.set_email" in _text_k and hasattr(auth_alt.store, "set_email")
        and "UPDATE users" in _text_k,
        f"{_text_k[:320]!r}")
r.check("...und keine Methode macht das UPDATE überflüssig",
        not any(hasattr(_o, _n) for _o in (auth_alt, auth_alt.store)
                for _n in ("set_username", "rename_user", "change_identifier")),
        "es gibt jetzt eine Umbenennungs-Methode — dann gehört sie in die Meldung statt des UPDATE")
r.check("...und verspricht dafür weder Admin-Panel noch CLI",
        "Kennungen ändern (Admin-Panel oder CLI)" not in _text_k
        and "weder im Admin-Panel noch im CLI" in _text_k,
        f"{_text_k[:320]!r} — die Admin-API kennt kein Umbenennen, das CLI keine Kontenverwaltung")

# Integration der Runde: Die Meldung nennt `store.set_email(...)` — und genau diese Methode nimmt
# seit B-umgehung-8 den Bestätigungs-Vermerk MIT (Vorgabe: unbestätigt). Wer der Meldung folgt, um
# eine Kollision am Konto eines Admins aufzulösen, löscht damit nebenbei den Beleg seiner Adresse.
# Das ist fail-closed und richtig — aber es darf den Betreiber nicht überraschen, und `verified=True`
# ist der Weg, einen echten Beleg zu behalten. Gemessen wird beides zusammen: der Satz in der
# Meldung UND das Verhalten dahinter. Fällt eines weg, wird die Prüfung rot.
r.check("...und sagt, dass store.set_email den Bestätigungs-Vermerk mitnimmt",
        "email_verified=0" in _text_k and "verified=True" in _text_k,
        f"{_text_k[:400]!r} — der Betreiber folgt der Meldung und verliert stillschweigend den Beleg")
auth_alt.store.set_email_verified(opfer_alt, True)
auth_alt.store.set_email(opfer_alt, "chef-neu@example.com")
r.check("...und so ist es auch: der genannte Weg legt die neue Adresse unbestätigt ab",
        auth_alt.store.get_user(opfer_alt)["email_verified"] == 0,
        "set_email lässt den Beleg der ALTEN Adresse stehen — dann ist die Meldung falsch, "
        "und ein Adresswechsel ist wieder ein Bootstrap-Weg (B-umgehung-8)")
auth_alt.store.set_email(opfer_alt, "chef-belegt@example.com", verified=True)
r.check("...und verified=True behält ihn, wie die Meldung verspricht",
        auth_alt.store.get_user(opfer_alt)["email_verified"] == 1,
        "verified=True trägt den Beleg nicht — dann nennt die Meldung einen Weg, den es nicht gibt")

# Gegenprobe, sonst wäre die Meldung Rauschen: In auth_n2 trägt EIN Konto denselben Wert in
# beiden eigenen Spalten (chef / chef@example.com) — das ist der vorgesehene Weg, keine Kollision.
r.check("eine Datenbank ohne Kreuz-Kollision schweigt",
        "Kennungs-Kollision" not in _start_log(auth_n2.cfg.db_path),
        "dieselbe Zeichenfolge in beiden Spalten DESSELBEN Kontos wird als Kollision gemeldet")
# ── Ein GET entfernt den bestätigten zweiten Faktor (B2-1, Audit-Runde 3) ────
# Angriff: Das Opfer ist voll angemeldet (Passwort + TOTP) und klickt auf einer fremden Seite
# einen Link auf /auth/totp/setup. Die Seite rief `totp_begin()` unbedingt und schrieb damit ein
# neues, unbestätigtes Geheimnis über das alte: TOTP fiel auf „unbestätigt", die zehn
# Recovery-Codes blieben verwaist liegen, es entstand keine Audit-Zeile — und danach genügte das
# Passwort allein. CSRF schützt hier nichts: Ein GET trägt kein Token, und `SameSite=Lax`
# (Vorgabe) schickt das Sitzungscookie bei einer Top-Level-Navigation mit.
import pyotp  # noqa: E402
import time

auth_b21, app_b21 = _app()
uid_b21 = auth_b21.create_user("nina", password="geheim12345", email="nina@example.com")
geheim_b21 = auth_b21.totp_begin(uid_b21)["secret"]
auth_b21.totp_confirm(uid_b21, pyotp.TOTP(geheim_b21).at(time.time() - 30))
codes_b21 = auth_b21.generate_recovery_codes(uid_b21)
c_b21 = TestClient(app_b21, base_url="https://app.example.com")
c_b21.get("/auth/login")
c_b21.post("/auth/login", data={"username": "nina", "password": "geheim12345", "next": "/",
                                "_csrf": c_b21.cookies.get(auth_b21.cfg.csrf_cookie)},
           follow_redirects=False)
c_b21.post("/auth/totp", data={"code": pyotp.TOTP(geheim_b21).now(), "next": "/",
                               "_csrf": c_b21.cookies.get(auth_b21.cfg.csrf_cookie)},
           follow_redirects=False)
sitzung_b21 = auth_b21.store.get_session(c_b21.cookies.get(auth_b21.cfg.session_cookie))

# Vorbedingung: Ohne diese drei Zeilen misst der Angriff unten nichts. Sie halten fest, dass
# hier wirklich ein vollwertiger zweiter Faktor steht, der verloren gehen KÖNNTE.
r.check("Vorbedingung: der zweite Faktor ist bestätigt",
        auth_b21.store.has_confirmed_totp(uid_b21), "ohne TOTP prüft der Angriff nichts")
r.check("Vorbedingung: zehn Recovery-Codes liegen dazu",
        auth_b21.store.count_recovery_codes(uid_b21) == len(codes_b21) == 10,
        f"{auth_b21.store.count_recovery_codes(uid_b21)}")
r.check("Vorbedingung: die Sitzung ist vollwertig (CSRF an, SameSite=Lax)",
        bool(sitzung_b21 and sitzung_b21["mfa_ok"]) and auth_b21.cfg.csrf_enabled
        and auth_b21.cfg.cookie_samesite == "lax",
        f"mfa_ok={sitzung_b21 and sitzung_b21['mfa_ok']} csrf={auth_b21.cfg.csrf_enabled}")

ant_b21 = c_b21.get("/auth/totp/setup", headers={"Sec-Fetch-Site": "cross-site",
                                                 "Sec-Fetch-Mode": "navigate"})
r.check("ein GET auf die Einrichtungsseite nimmt kein bestätigtes TOTP zurück",
        ant_b21.status_code == 409,
        f"HTTP {ant_b21.status_code} — ein Klick auf einen fremden Link genügt sonst")
r.check("...der zweite Faktor steht danach noch", auth_b21.store.has_confirmed_totp(uid_b21),
        "TOTP ist auf unbestätigt zurückgefallen, das Passwort allein reicht wieder")
r.check("...und die Recovery-Codes gehören weiter zu einem gültigen Faktor",
        auth_b21.store.count_recovery_codes(uid_b21) == 10
        and auth_b21.store.has_confirmed_totp(uid_b21)
        and auth_b21.verify_recovery_code(uid_b21, codes_b21[0]),
        f"{auth_b21.store.count_recovery_codes(uid_b21)} Codes ohne bestätigtes TOTP = verwaist")

# Nicht nur die Route: Der Wächter sitzt im Manager, damit ihn keine eigene Oberfläche umgeht.
try:
    auth_b21.totp_begin(uid_b21)
    geworfen = ""
except StateError as exc:
    geworfen = str(exc)
r.check("auch totp_begin() selbst verweigert das Überschreiben", bool(geworfen),
        "die Methode schreibt weiter durch — jede eigene Oberfläche reisst dieselbe Lücke auf")
r.check("der abgewehrte Versuch steht im Audit-Log",
        any(z["event"] == "totp_setup_denied" for z in auth_b21.store.recent_audit(50)),
        "der Versuch hinterlässt keine Spur")

# ── Dieselbe Tür, zweite Hälfte: der GET erzeugte weiter Geheimnisse ─────────
# Der Fundtext zu B2-1 verlangt ZWEI Dinge: bei bestätigtem TOTP verweigern **und** die
# Einrichtung nur auf ausdrückliche Anforderung (POST mit CSRF-Token) beginnen. Zunächst war
# nur das Erste umgesetzt: Für ein Konto OHNE bestätigtes TOTP erzeugte jeder GET auf
# /auth/totp/setup ein frisches Geheimnis und ersetzte damit einen laufenden
# Einrichtungsversuch. Kein Faktor-Verlust — aber ein fremder Link entwertete das eben
# gescannte QR-Bild (die Bestätigung schlug danach unerklärlich fehl) und stiess
# Audit-Zeilen von aussen an.
auth_b7, app_b7 = _app()
uid_b7 = auth_b7.create_user("paul", password="geheim12345")
c_b7 = TestClient(app_b7, base_url="https://app.example.com")
c_b7.cookies.set(auth_b7.cfg.session_cookie,
                 auth_b7.store.create_session(uid_b7, 3600, True, "password"))
r.check("Vorbedingung: CSRF ist an und das Sitzungscookie ist SameSite=Lax",
        auth_b7.cfg.csrf_enabled and auth_b7.cfg.cookie_samesite == "lax",
        "ohne diese Lage trägt ein fremder Link das Cookie nicht mit — der Test misst nichts")
seite_b7 = c_b7.get("/auth/totp/setup")
r.check("ein GET auf die Einrichtungsseite erzeugt kein Geheimnis",
        seite_b7.status_code == 200 and auth_b7.store.get_totp(uid_b7) is None,
        f"HTTP {seite_b7.status_code}, Geheimnis={auth_b7.store.get_totp(uid_b7) is not None} "
        "— ein GET, der schreibt, ist von aussen anstossbar")
r.check("...die Seite zeigt stattdessen den Knopf, der sie ausdrücklich startet",
        "/auth/totp/setup/start" in seite_b7.text, "ohne Knopf ist die Einrichtung zugemauert")
r.check("...und hinterlässt keine Audit-Zeile",
        not any(z["event"] == "totp_setup_start" for z in auth_b7.store.recent_audit(20)),
        "Audit-Rauschen, das jeder von aussen erzeugen kann")
csrf_b7 = c_b7.cookies.get(auth_b7.cfg.csrf_cookie)
start_b7 = c_b7.post("/auth/totp/setup/start", data={"_csrf": csrf_b7})
zeile_b7 = auth_b7.store.get_totp(uid_b7)
r.check("der POST mit CSRF-Token richtet ein", start_b7.status_code == 200 and zeile_b7 is not None,
        f"HTTP {start_b7.status_code}: {start_b7.text[:120]}")
# B2-1 hat auch die Audit-Zeile versprochen — bis 0.18.x war die TOTP-Einrichtung unsichtbar.
r.check("...und die Einrichtung steht im Audit-Log",
        any(z["event"] == "totp_setup_start" for z in auth_b7.store.recent_audit(20)),
        "die Einrichtung eines zweiten Faktors hinterlässt keine Spur")
vorher_b7 = zeile_b7["secret"]
fremd_b7 = c_b7.post("/auth/totp/setup/start", data={})           # kein Token = fremde Seite
r.check("ein POST ohne CSRF-Token ersetzt das laufende Geheimnis nicht",
        fremd_b7.status_code == 403 and auth_b7.store.get_totp(uid_b7)["secret"] == vorher_b7,
        f"HTTP {fremd_b7.status_code} — das gescannte QR-Bild ist von aussen entwertbar")
quer_b7 = c_b7.get("/auth/totp/setup", headers={"Sec-Fetch-Site": "cross-site",
                                                "Sec-Fetch-Mode": "navigate"})
r.check("...und ein Klick auf einen fremden Link genauso wenig",
        quer_b7.status_code == 200 and auth_b7.store.get_totp(uid_b7)["secret"] == vorher_b7,
        "der GET hat das Geheimnis ersetzt")
r.check("...die Bestätigung mit dem Code aus DIESEM Geheimnis schaltet scharf",
        auth_b7.totp_confirm(uid_b7, pyotp.TOTP(vorher_b7).at(time.time() - 30))
        and auth_b7.store.has_confirmed_totp(uid_b7),
        "der legitime Weg ist unterbrochen")

# Der legitime Weg muss bleiben: einrichten, wo noch nichts ist …
auth_ok, app_ok = _app(csrf_enabled=False)
uid_ok = auth_ok.create_user("tom", password="geheim12345")
c_ok = TestClient(app_ok, follow_redirects=False)
c_ok.cookies.set(auth_ok.cfg.session_cookie,
                 auth_ok.store.create_session(uid_ok, 3600, True, "password"))
r.check("ohne eingerichtetes TOTP ist die Einrichtungsseite weiter erreichbar",
        c_ok.get("/auth/totp/setup").status_code == 200, "die Einrichtung ist zugemauert")
r.check("...und der Start-Knopf richtet ein",
        c_ok.post("/auth/totp/setup/start").status_code == 200
        and auth_ok.store.get_totp(uid_ok) is not None, "die Einrichtung ist zugemauert")
neu_ok = auth_ok.store.get_totp(uid_ok)["secret"]
r.check("...und die Bestätigung schaltet den Faktor scharf",
        auth_ok.totp_confirm(uid_ok, pyotp.TOTP(neu_ok).at(time.time() - 30))
        and auth_ok.store.has_confirmed_totp(uid_ok))

# … und nach dem regulären Abschalten wieder neu einrichten (sonst wäre der Fix eine Sackgasse).
auth_ok.totp_disable(uid_ok)
r.check("nach dem regulären Abschalten ist die Einrichtung wieder offen",
        c_ok.get("/auth/totp/setup").status_code == 200
        and c_ok.post("/auth/totp/setup/start").status_code == 200,
        "der Wechsel des Authenticators wäre unmöglich")

# Verwaiste Recovery-Codes (Geheimnis weg, Codes noch da) räumt die Einrichtung ab.
auth_v, _ = _app()
uid_v = auth_v.create_user("vera", password="geheim12345")
geheim_v = auth_v.totp_begin(uid_v)["secret"]
auth_v.totp_confirm(uid_v, pyotp.TOTP(geheim_v).at(time.time() - 30))
auth_v.generate_recovery_codes(uid_v)
auth_v.store.delete_totp(uid_v)          # nur das Geheimnis weg — die Codes bleiben zurück
auth_v.totp_begin(uid_v)
r.check("eine neue Einrichtung lässt keine verwaisten Recovery-Codes stehen",
        auth_v.store.count_recovery_codes(uid_v) == 0,
        f"{auth_v.store.count_recovery_codes(uid_v)} Codes gelten weiter, "
        "obwohl sie zu keinem Authenticator mehr passen")
# ── Ein Rückwärtssprung der Uhr belebte Abgelaufenes (B6-9) ──────────────────
# NTP-Korrektur, ein Pi ohne Pufferbatterie, ein VM-Snapshot: Die Wanduhr springt zurück, und
# jede Frist in der Datenbank wurde neu verhandelt — abgelaufene Sitzungen galten wieder, ein
# verfallener Magic-Link liess sich einlösen, ein alter Step-up war wieder „frisch".
from tinysesam import store as _store_mod  # noqa: E402

# Die Uhr für sich, mit gestellter Wand- und Monotonzeit.
_w, _m = [1000.0], [0.0]
_u = _store_mod._Uhr(wand=lambda: _w[0], mono=lambda: _m[0])
_folge = [_u.jetzt()]
_w[0], _m[0] = 400.0, 10.0          # Sprung 600 s zurück, 10 s sind wirklich vergangen
_folge.append(_u.jetzt())
_w[0], _m[0] = 2000.0, 20.0         # die Wanduhr springt nach vorn (NTP nach dem Boot)
_folge.append(_u.jetzt())
r.check("die Uhr zählt nach einem Rückwärtssprung monoton weiter und folgt nach vorn",
        _folge == [1000, 1010, 2000], f"{_folge}")

auth_u, _ = _app()
uid_u = auth_u.create_user("uhrzeit", password="geheim12345")
tok_u = auth_u.store.create_session(uid_u, 3600, True, "password")
roh_magic = auth_u.create_magic_token("login", user_id=uid_u, ttl_min=10)
jetzt_u = _store_mod.jetzt()
# Beides ist vor 60 s abgelaufen …
auth_u.store._exec("UPDATE session SET expires_at=? WHERE token_hash=?",
                   (jetzt_u - 60, auth_u.store.session_hash(tok_u)))
auth_u.store._exec("UPDATE magic_token SET expires_at=?", (jetzt_u - 60,))
# … und dann springt die Wanduhr eine Stunde zurück.
_echt = _store_mod._UHR.wand
_store_mod._UHR.wand = lambda: _echt() - 3600
try:
    r.check("eine abgelaufene Sitzung bleibt nach einem Rückwärtssprung abgelaufen",
            auth_u.store.get_session(tok_u) is None, "die Sitzung lebt wieder auf")
    r.check("ein verfallener Magic-Link bleibt verfallen",
            auth_u.redeem_magic(roh_magic, "login") is None, "der Link lässt sich wieder einlösen")
finally:
    _store_mod._UHR.wand = _echt

# Über einen Neustart: Die Datenbank trägt den Stand. Frische Uhr, Wanduhr eine Stunde zurück.
auth_n, _ = _app()
uid_n = auth_n.create_user("neustart", password="geheim12345")
tok_n = auth_n.store.create_session(uid_n, 3600, True, "password")
jetzt_n = _store_mod.jetzt()
auth_n.store._exec("UPDATE session SET expires_at=? WHERE token_hash=?",
                   (jetzt_n - 60, auth_n.store.session_hash(tok_n)))
auth_n.store.db.close()
_alte_uhr = _store_mod._UHR
_store_mod._UHR = _store_mod._Uhr(wand=lambda: _echt() - 3600)
_uhr_log = io.StringIO()
_uhr_h = logging.StreamHandler(_uhr_log)
logging.getLogger("tinysesam").addHandler(_uhr_h)
try:
    st_n = _store_mod.Store(auth_n.cfg.db_path)
    r.check("nach einem Neustart mit zurückgestellter Uhr bleibt die Sitzung abgelaufen",
            st_n.get_session(tok_n) is None, "der Neustart hat die Frist vergessen")
    r.check("…und der Rückstand der Systemuhr steht im Log",
            "Systemuhr" in _uhr_log.getvalue(), _uhr_log.getvalue()[:200])
    st_n.db.close()
finally:
    _store_mod._UHR = _alte_uhr
    logging.getLogger("tinysesam").removeHandler(_uhr_h)

# Über einen Neustart bis zum zuletzt GESICHERTEN Stand, nicht nur bis zum letzten Ereignis
# (A-B6-9-neustart): Ein Link und eine Sitzung, zwei Stunden vor dem Neustart abgelaufen, ohne
# dass danach etwas angelegt wurde. Der Pi bootet mit einem Datum ein Jahr zurück. Vorher kannte
# `Store()` nur MAX(created_at/ts) und hob die Uhr auf den Zeitpunkt der Anlage — beide galten
# wieder für ihre volle Restfrist.
_T = 1_800_000_000.0
_wand_n = [_T]


def _neustart_nach_2h(sichern):
    """Legt Link + Sitzung bei T an, lässt 2 h vergehen, `sichern(store)` sichert (oder nicht),
    startet mit einem Jahr zurückgestellter Uhr neu. → (link gilt?, sitzung gilt?, uhr_stand)"""
    _store_mod._UHR = _store_mod._Uhr(wand=lambda: _wand_n[0])
    _wand_n[0] = _T
    a = TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "n.db"),
                                  cookie_secure=False))
    uid = a.create_user("pi", password="geheim12345")
    roh = a.create_magic_token("login", user_id=uid, ttl_min=15)
    tok = a.store.create_session(uid, 1800, False, "password")
    _wand_n[0] = _T + 7200
    sichern(a.store)
    a.store.db.close()
    _store_mod._UHR = _store_mod._Uhr(wand=lambda: _T - 365 * 86400)
    a.store = _store_mod.Store(a.cfg.db_path)
    gilt = (a.peek_magic(roh, purpose="login") is not None, a.store.get_session(tok) is not None)
    # Ein Schreiber, dessen Uhr NICHT gehoben ist (ein zweiter Prozess auf derselben Datei, vor
    # der Sicherung gestartet), darf den gesicherten Stand nicht nach unten überschreiben.
    _store_mod._UHR = _store_mod._Uhr(wand=lambda: _T - 365 * 86400)
    a.store.UHR_SICHERN_SEK = 0
    a.create_user("nach-dem-boot")
    stand = int(a.store.get_setting(a.store.UHR_STAND) or 0)
    a.store.db.close()
    return gilt + (stand,)


def _per_healthcheck(st):
    st._geschrieben = None                   # die Probe ist fällig, wie alle 30 s im Container
    st.schreibprobe()


def _per_schreibzugriff(st):
    st.UHR_SICHERN_SEK = 0                   # „eine Minute ist vergangen"
    st.set_setting("irgendwas", "1")


logging.getLogger("tinysesam").addHandler(_uhr_h)
try:
    _hc = _neustart_nach_2h(_per_healthcheck)
    _sz = _neustart_nach_2h(_per_schreibzugriff)
finally:
    _store_mod._UHR = _alte_uhr
    logging.getLogger("tinysesam").removeHandler(_uhr_h)
r.check("nach einem Neustart bleibt, was NACH dem letzten Ereignis ablief, abgelaufen "
        "(Stand aus der Schreibprobe des Healthchecks)",
        _hc[:2] == (False, False), f"Link gilt: {_hc[0]}, Sitzung gilt: {_hc[1]}")
r.check("…ebenso mit dem Stand, den ein gewöhnlicher Schreibzugriff mitsichert",
        _sz[:2] == (False, False), f"Link gilt: {_sz[0]}, Sitzung gilt: {_sz[1]}")
r.check("ein Schreiber mit ungehobener Uhr setzt den gesicherten Stand nicht zurück",
        _hc[2] >= _T + 7200 and _sz[2] >= _T + 7200, f"uhr_stand={_hc[2]}/{_sz[2]}")

# `time.time` wird nicht beim Import gebunden (A-B6-9-zeitpatch): Eine einbettende App, die in
# ihren Tests die Zeit vorstellt, stellt damit auch TinySesams Uhr vor. Gebunden sah TinySesam den
# Patch nie — Sitzungen und Tokens liefen im Test der App nie ab.
from unittest import mock  # noqa: E402
import time as _time  # noqa: E402
_store_mod._UHR = _store_mod._Uhr()          # frische Uhr: der Sprung soll im Prozess nicht bleiben
try:
    auth_p, _ = _app()
    uid_p = auth_p.create_user("zeitpatch", password="geheim12345")
    tok_p = auth_p.store.create_session(uid_p, 60, False, "password")
    _echt_t = _time.time()
    with mock.patch("time.time", lambda: _echt_t + 3600):
        _gilt_p = auth_p.store.get_session(tok_p) is not None
finally:
    _store_mod._UHR = _alte_uhr
r.check("mock.patch('time.time') nach vorn lässt eine Sitzung ablaufen",
        not _gilt_p, "TinySesam sieht die gepatchte Zeit nicht (beim Import gebunden)")


# ── pop_flow gab dieselbe Challenge zweimal heraus (R3-8) ────────────────────
# Lesen und Löschen waren zwei Schritte. Zwei Callbacks mit demselben OIDC-`state` (zwei
# Threads, zwei Worker auf derselben Datei) lasen beide, bevor einer löschte. Nachgestellt
# deterministisch: Zwischen dem SELECT des ersten und seinem DELETE verbraucht ein zweiter
# Worker (eigene Verbindung, dieselbe Datei) denselben Schlüssel.
auth_f, _ = _app()
st_a = auth_f.store
st_b = _store_mod.Store(auth_f.cfg.db_path)
st_a.put_flow("oidc:zustand", {"nonce": "n-1"})


class _Dazwischen:
    """Verbindung, die nach dem Lesen des Flows den zweiten Worker zum Zug kommen lässt."""

    def __init__(self, db):
        self._db, self.zweiter = db, None

    def execute(self, sql, *args):
        cur = self._db.execute(sql, *args)
        if sql.startswith("SELECT data, expires_at FROM flow") and self.zweiter is None:
            self.zweiter = st_b.pop_flow("oidc:zustand")
        return cur

    def __getattr__(self, name):
        return getattr(self._db, name)


_zw = _Dazwischen(st_a.db)
st_a.db = _zw
erster = st_a.pop_flow("oidc:zustand")
st_a.db = _zw._db
r.check("der zweite Worker bekommt den Flow-State", _zw.zweiter == {"nonce": "n-1"}, f"{_zw.zweiter}")
r.check("…und der erste dann nicht mehr — genau einer gewinnt",
        erster is None, f"beide haben {erster} bekommen: Challenge/state doppelt verbraucht")
st_a.put_flow("oidc:einfach", {"x": 1})
r.check("ohne Wettlauf kommt der Flow genau einmal heraus",
        st_a.pop_flow("oidc:einfach") == {"x": 1} and st_a.pop_flow("oidc:einfach") is None)
st_b.db.close()


# ── SQLite wartete nach einer unbewussten Vorgabe (B6-11) ─────────────────────
# Wie lange ein zweiter Schreiber wartet, bevor eine Anmeldung mit „database is locked"
# scheitert, war Pythons stille Vorgabe (5 s). Jetzt ausdrücklich — und an der Verbindung lesbar.
import sqlite3 as _sqlite3  # noqa: E402
import threading as _threading  # noqa: E402

auth_b, _ = _app()
bt = auth_b.store.db.execute("PRAGMA busy_timeout").fetchone()[0]
r.check("busy_timeout ist bewusst gesetzt (Store.BUSY_TIMEOUT_MS, über Pythons 5 s)",
        bt == _store_mod.Store.BUSY_TIMEOUT_MS and bt > 5000, f"busy_timeout={bt}")
fremd = _sqlite3.connect(auth_b.cfg.db_path, isolation_level=None, check_same_thread=False)
fremd.execute("BEGIN IMMEDIATE")                  # ein zweiter Schreiber hält die Sperre …
_frei = _threading.Timer(0.5, lambda: fremd.execute("COMMIT"))
_frei.start()
try:
    auth_b.store.put_flow("warten", {"ok": True})  # … und dieser Schreiber wartet, statt zu scheitern
    gewartet = True
except _sqlite3.OperationalError as e:
    gewartet = str(e)
_frei.join(timeout=5)
fremd.close()
r.check("ein Schreiber wartet auf eine kurz gehaltene Sperre, statt abzubrechen",
        gewartet is True, f"{gewartet}")

# ── H-18 (a): ein gesperrtes Konto kommt über KEINEN Weg zu einer Sitzung ────────
# Jeder Weg hatte seine eigene `disabled`-Prüfung — oder eben nicht: Anmelde-Link und Passkey
# legten für ein gesperrtes Konto eine Sitzung an (erst `current_user()` verwarf sie wieder),
# und ein offener Bestätigungslink aus der Registrierung hob die Sperre des Betreibers sogar
# auf. Gemessen wird deshalb die Klasse: alle Wege, danach die Frage „gibt es eine neue Sitzung?".
from fastapi import HTTPException as _HTTPException  # noqa: E402
from starlette.requests import Request as _Request  # noqa: E402

auth_g, app_g = _app(csrf_enabled=False, pin_enabled=True, pin_login=True,
                     magiclink_enabled=True, apikey_enabled=True, passkey_enabled=False,
                     allow_signup=True, signup_require_email=True, signup_verify_email=True,
                     base_url=ECHT)
auth_g.set_mailer(lambda to, betreff, text, html=None: None)
uid_g = auth_g.create_user("gesperrt", password="Geheim12345!", email="gesperrt@example.com")
auth_g.set_pin(uid_g, "471193")
key_g = auth_g.create_api_key(uid_g, "bot")["key"]
alt_g = auth_g.store.create_session(uid_g, 3600, True, "password")
magic_g = auth_g.create_magic_token("login", user_id=uid_g, email="gesperrt@example.com")
# Direkt im Store gesperrt, nicht über das Panel: Die Token und die alte Sitzung bleiben so
# stehen — geprüft wird, dass kein WEG sie nutzen kann, nicht, dass das Panel aufräumt.
auth_g.store.set_disabled(uid_g, True)


@app_g.get("/geschuetzt")
def _geschuetzt_g(u=Depends(auth_g.require_user)):
    return {"u": u["username"]}


def _sitzungen_g():
    return {z["token_hash"] for z in auth_g.store.list_sessions(uid_g)}


vorher_g = _sitzungen_g()
cg = TestClient(app_g)
cg.post("/auth/login", data={"username": "gesperrt", "password": "Geheim12345!", "next": "/"},
        follow_redirects=False)
cg.post("/auth/pin", data={"username": "gesperrt", "pin": "471193", "next": "/"},
        follow_redirects=False)
magic_antwort = cg.get(f"/auth/magic/{magic_g}", follow_redirects=False)
r.check("Anmelde-Link eines gesperrten Kontos wird abgewiesen",
        magic_antwort.status_code == 403, f"HTTP {magic_antwort.status_code}")

# Die Wege, die hier nicht als Route laufen (Passkey, OIDC, SAML, LDAP, Kette), enden alle in
# `apply_factor` — dort sitzt der Riegel für die ganze Klasse.
_leer = _Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
_durch = []
for _faktor in ("password", "pin", "passkey", "oidc", "saml", "magic", "totp"):
    try:
        auth_g.apply_factor(_leer, uid_g, _faktor, "198.51.100.7")
        _durch.append(_faktor)
    except _HTTPException as e:
        if e.status_code != 403:
            _durch.append(f"{_faktor}:{e.status_code}")
r.check("apply_factor verweigert einem gesperrten Konto jeden Faktor", not _durch,
        f"durchgelassen: {_durch}")
r.check("…und jeder abgewiesene Versuch steht im Audit-Log (login_disabled)",
        sum(z["event"] == "login_disabled" for z in auth_g.store.recent_audit(50)) >= 8,
        f"{[z['event'] for z in auth_g.store.recent_audit(20)]}")
r.check("…und über keinen Weg ist eine neue Sitzung entstanden", _sitzungen_g() == vorher_g,
        f"{len(_sitzungen_g() - vorher_g)} neue Sitzung(en) für ein gesperrtes Konto")
cg.cookies.set(auth_g.cfg.session_cookie, alt_g)
r.check("eine Sitzung von vor der Sperre öffnet nichts mehr",
        cg.get("/geschuetzt").status_code == 401)
cg.cookies.clear()
r.check("ein API-Key des gesperrten Kontos öffnet nichts",
        cg.get("/geschuetzt", headers={"X-API-Key": key_g}).status_code == 401)

# Die halbe Sitzung (erster Faktor erbracht, TOTP offen) wird nach einer Sperre nicht vollwertig.
uid_h = auth_g.create_user("halb", password="Geheim12345!")
halb_tok = auth_g.store.create_session(uid_h, 3600, False, "password")
auth_g.store.set_disabled(uid_h, True)
r.check("eine halbe Sitzung wird nach der Sperre nicht über TOTP vollwertig",
        auth_g.complete_totp(halb_tok) is None and auth_g.store.get_session(halb_tok) is None,
        "complete_totp stellte einem gesperrten Konto eine volle Sitzung aus")

# Die Sperre durch den Betreiber hält gegen einen offenen Bestätigungslink.
admin_g = auth_g.create_user("chefin-g", password="Geheim12345!", is_admin=True)
uid_v = auth_g.create_user("wartend", password="Geheim12345!", email="wartend@example.com")
auth_g.store.set_disabled(uid_v, True)                      # wie nach der Registrierung
verify_g = auth_g.create_magic_token("verify_email", user_id=uid_v, email="wartend@example.com")
ca_g = TestClient(app_g)
ca_g.cookies.set(auth_g.cfg.session_cookie, auth_g.store.create_session(admin_g, 3600, True, "password"))
ca_g.post(f"/auth/admin/api/users/{uid_v}/disable", json={"disabled": True})
cv = TestClient(app_g)
cv.get(f"/auth/verify/{verify_g}", follow_redirects=False)
r.check("ein Bestätigungslink hebt eine Sperre des Betreibers nicht auf",
        bool(auth_g.store.get_user(uid_v)["disabled"]),
        "der Link aus der Registrierung hat das gesperrte Konto wieder freigeschaltet")


# ── H-18 (c): jeder Mail-Link entsteht aus `base_url` — auch künftige ─────────────
# Die fünf Wege oben (`_wege`) sind eine Liste von Hand. Ein sechster Absender fiele dort nicht
# auf. Deshalb mechanisch: Jede Funktion im Paket, die `send_mail()` oder `magic_url()` ruft,
# muss in dieser Liste stehen — sonst verschickt sie Links, deren Basis niemand gemessen hat.
import ast as _ast  # noqa: E402

_GEMESSEN = {name for name, _ in _wege(_a_api, ECHT)} | {"send_mail", "magic_url"}
_absender = set()
for _datei in sorted((ROOT / "tinysesam").glob("*.py")):
    _baum = _ast.parse(_datei.read_text(encoding="utf-8"))
    for _fn in _ast.walk(_baum):
        if not isinstance(_fn, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue
        for _k in _ast.walk(_fn):
            if (isinstance(_k, _ast.Call) and isinstance(_k.func, _ast.Attribute)
                    and _k.func.attr in ("send_mail", "magic_url")):
                _absender.add(_fn.name)
r.check("Wächter: er findet die bekannten Absender überhaupt",
        {"send_password_reset", "send_login_link", "send_verify_email", "create_invite"} <= _absender,
        f"gefunden: {sorted(_absender)} — ohne Treffer prüft die Zeile darunter nichts")
r.check("jeder Absender von Mail-Links steht in der gemessenen Liste",
        _absender <= _GEMESSEN, f"ungemessen: {sorted(_absender - _GEMESSEN)} — in `_wege` aufnehmen")


# ── Konfigurationsprüfung, T-13-Bereich „Admin und Konfiguration" ──────────────
from tinysesam import konfigpruefung as _kp2, security as _sec2  # noqa: E402


def _befund(**cfg):
    """(Fehler, Warnungen) für eine Config mit Wegwerf-Datenbank."""
    cfg.setdefault("db_path", ":memory:")
    return _kp2.pruefe(TinySesamConfig(**cfg))


def _nennt(liste, *woerter):
    return any(all(w in x for w in woerter) for x in liste)


# B3-3: ein ungültiger trusted_proxies-Eintrag entwertet nicht mehr die ganze Liste …
r.check("B3-3: gültiger Eintrag trägt neben einem ungültigen",
        _sec2.is_trusted("198.51.100.7", ["proxy.intern", "198.51.100.0/24"]),
        "ein Hostname in der Liste warf, und der echte Proxy galt als fremd")
# (Mutationsprobe: is_trusted wieder mit einem `try` um das ganze any() → rot.)
r.check("...und die Konfigurationsprüfung weist die Liste ab",
        _nennt(_befund(trusted_proxies=["proxy.intern", "198.51.100.0/24"])[0], "trusted_proxies", "proxy.intern"))
r.check("...die Vorgabe und echte Netze bleiben ohne Befund",
        not _nennt(sum(_befund(trusted_proxies=["198.51.100.0/24", "::1"]), []), "trusted_proxies"))

# B3-6: stepup_methods wird geprüft — ein Tippfehler entfernt den zweiten Faktor nicht mehr still.
r.check("B3-6: unbekanntes Step-up-Verfahren ist ein Fehler",
        _nennt(_befund(stepup_methods=["topt"])[0], "stepup_methods", "topt"))
r.check("...ein abgeschaltetes ebenso (pin ohne pin_enabled)",
        _nennt(_befund(stepup_methods=["pin"])[0], "pin_enabled=False"))
r.check("...gültige Werte bleiben ohne Befund",
        not _nennt(sum(_befund(stepup_methods=["totp", "pin"], pin_enabled=True), []), "stepup_methods"))
try:
    TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), stepup_methods=["topt"]))
    _b36 = False
except _CfgErr:
    _b36 = True
r.check("...und der Aufbau scheitert daran", _b36)

# B3-10: rp_id/origin werden betrachtet.
r.check("B3-10: rp_id, die nicht zum origin passt, ist ein Fehler",
        _nennt(_befund(passkey_enabled=True, rp_id="example.org", origin="https://auth.example.com")[0],
               "rp_id", "passt nicht"))
r.check("...origin mit Pfad ist kein Origin",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com",
                       origin="https://auth.example.com/login")[0], "ist kein Origin"))
r.check("...Entwicklerwerte neben einer öffentlichen base_url werden gemeldet",
        _nennt(_befund(passkey_enabled=True, base_url="https://auth.example.com")[1], "origin", "base_url"))
r.check("...passende Werte bleiben ohne Befund",
        not _nennt(sum(_befund(passkey_enabled=True, rp_id="example.com", origin="https://auth.example.com",
                               base_url="https://auth.example.com"), []), "origin"))

# B3-12: Zahlenfelder mit Grenzen.
for _feld, _wert in (("session_ttl_hours", 0), ("magiclink_ttl_min", 0), ("recovery_code_count", 0),
                     ("stepup_max_age_sec", -1), ("smtp_port", 70000), ("pin_min_length", 2),
                     ("session_ttl_hours", True)):
    r.check(f"B3-12: {_feld}={_wert!r} ist ein Fehler", _nennt(_befund(**{_feld: _wert})[0], _feld))
r.check("...die Vorgaben selbst liegen alle in ihren Grenzen",
        not any(f in x for x in _befund()[0] for f in _kp2.ZAHLENGRENZEN))
# (Mutationsprobe: `_zahlengrenzen(config, fehler)` in pruefe() auskommentieren → rot.)

# H-11 / B3-9: deny-by-default am Forward-Auth-Tor.
_gw = TinySesamConfig.oidc_gateway(issuer="https://id.example.com", client_id="g", client_secret="s",
                                   base_url="https://auth.example.com", db_path=":memory:")
r.check("H-11/B3-9: Gateway-Preset ohne Gruppen und ohne Clients warnt vor dem offenen Tor",
        _nennt(_kp2.pruefe(_gw)[1], "offenem Tor", "OIDC"))
_gw2 = TinySesamConfig.oidc_gateway(issuer="https://id.example.com", client_id="g", client_secret="s",
                                    base_url="https://auth.example.com", db_path=":memory:",
                                    allowed_groups=["mitarbeiter"])
r.check("...mit allowed_groups schweigt die Warnung", not _nennt(_kp2.pruefe(_gw2)[1], "offenem Tor"))
r.check("...offene Registrierung vor Forward-Auth wird gemeldet",
        _nennt(_befund(forward_auth_enabled=True, allow_signup=True)[1], "Selbst-Registrierung"))
r.check("...ohne Forward-Auth kein Tor, keine Meldung",
        not _nennt(_befund(allow_signup=True)[1], "Selbst-Registrierung"))

# B3-16: Kombinationen.
r.check("B3-16: E-Mail-Bestätigung ohne Pflicht-Adresse ist ein Fehler",
        _nennt(_befund(allow_signup=True, signup_verify_email=True, signup_require_email=False,
                       base_url="https://auth.example.com")[0], "signup_require_email=False"))
r.check("...cookie_domain, die base_url nicht umfasst, ist ein Fehler",
        _nennt(_befund(cookie_domain=".example.org", base_url="https://auth.example.com")[0], "cookie_domain"))
r.check("...admin_path ohne führenden Schrägstrich ist ein Fehler",
        _nennt(_befund(admin_path="admin")[0], "admin_path"))
r.check("...kürzere Sitzung ohne „Angemeldet bleiben“ als mit wird gemeldet",
        _nennt(_befund(session_ttl_hours=2, session_ttl_transient_hours=12)[1], "session_ttl_transient_hours"))

# B3-8: Demo-Modus hat technische Schranken.
r.check("B3-8: demo_mode neben einem echten Anmeldeweg ist ein Fehler",
        _nennt(_befund(demo_mode=True, forward_auth_enabled=True)[0], "demo_mode"))
_demo_db = str(Path(tempfile.mkdtemp()) / "t.db")
_bestand = TinySesam(TinySesamConfig(db_path=_demo_db))
_bestand.create_user("echt", password="Geheim12345!")
try:
    TinySesam(TinySesamConfig(db_path=_demo_db, demo_mode=True))
    _b38 = False
except _CfgErr:
    _b38 = True
r.check("...demo_mode auf einer Datenbank mit Bestandskonten scheitert beim Aufbau",
        _b38 and _bestand.store.get_user_by_name("demoadmin") is None,
        "vorher entstand dort still ein Admin mit bekanntem Passwort")
# Gegenprobe: Eine echte Demo startet wieder, auch mit inzwischen registrierten Besuchern.
_demo_db2 = str(Path(tempfile.mkdtemp()) / "t.db")
_d1 = TinySesam(TinySesamConfig(db_path=_demo_db2, demo_mode=True))
_d1.create_user("besucher", password="Geheim12345!")
try:
    TinySesam(TinySesamConfig(db_path=_demo_db2, demo_mode=True))
    _b38b = True
except _CfgErr:
    _b38b = False
r.check("...eine echte Demo startet trotzdem neu (auch mit Besuchern)", _b38b)
# (Mutationsprobe: die Bestandsprüfung vor seed_demo im Konstruktor entfernen → rot.)

# B3-14: pruefen() hat einen Aufrufer — router() prüft vor dem Bau erneut.
_a314, _ = _app()
_a314.cfg.cookie_samesite = "Strict"
try:
    _a314.router()
    _b314 = False
except _CfgErr as _e:
    _b314 = "cookie_samesite" in str(_e)
r.check("B3-14: eine nach dem Konstruktor kaputt gestellte Config scheitert an router()", _b314)
_a314b, _ = _app()
_a314b.cfg.base_url = "https://auth.example.com"          # erlaubte Änderung
_a314b.cfg.lang = "de"
try:
    _a314b.router()
    _b314b = True
except _CfgErr:
    _b314b = False
r.check("...eine erlaubte Änderung (Sprache, Adresse) baut weiter", _b314b)
r.check("...und pruefen() liefert weiter eine Liste (Fehler + Warnungen)",
        isinstance(TinySesamConfig(db_path=":memory:").pruefen(), list))
# (Mutationsprobe: `self._nachpruefen()` in router() entfernen → rot.)

# A2: Auch die Riegel des Konstruktors gelten vor router()/admin_router(), nicht nur konfigpruefung.
# Angriff: admin_identifiers=["chef"] ist sicher, solange Konten nicht von selbst entstehen. Wer
# NACH dem Konstruktor allow_signup einschaltete, baute trotzdem einen Router — der erste Besucher
# registrierte sich als „chef" und war Erst-Admin mit Zugriff auf die Admin-API.
def _nachtraeglich(aenderung, **cfg):
    a, _ = _app(**cfg)
    for k, v in aenderung.items():
        setattr(a.cfg, k, v)
    ergebnis = []
    for bau in (a.router, a.admin_router):
        try:
            bau()
            ergebnis.append("")
        except _CfgErr as e:
            ergebnis.append(str(e))
    return ergebnis


for _titel, _aend, _cfg, _wort in (
        ("admin_identifiers + allow_signup", {"allow_signup": True}, {"admin_identifiers": ["chef"]},
         "admin_identifiers"),
        ("admin_identifiers + oidc_auto_create", {"oidc_enabled": True, "oidc_auto_create": True},
         {"admin_identifiers": ["chef"], "base_url": "https://auth.example.com"}, "admin_identifiers"),
        ("login_identifier='bogus'", {"login_identifier": "bogus"}, {}, "login_identifier"),
        ("forward_headers mit Zeilenumbruch", {"forward_headers": {"user": "X-User\r\nSet-Cookie: a=b"}}, {},
         "forward_headers"),
        ("totp_required=True", {"totp_required": True}, {}, "totp_required")):
    _erg = _nachtraeglich(_aend, **_cfg)
    r.check(f"A2: nachträglich {_titel} scheitert an router() und admin_router()",
            all(_wort in x and "nach dem Aufbau" in x for x in _erg), f"{_erg}")
# Der Angriff selbst: Mit dem Riegel entsteht gar kein Router, also auch keine Registrierung.
_a2, _ = _app(admin_identifiers=["chef"], csrf_enabled=False, signup_require_email=False)
_a2.cfg.allow_signup = True
_admin_api = None
try:
    _app2 = FastAPI()
    _app2.include_router(_a2.router())
    with TestClient(_app2) as _c2:
        _c2.post("/auth/register", data={"username": "chef", "password": "Fremder-123456"})
        _c2.post("/auth/login", data={"username": "chef", "password": "Fremder-123456"})
        _admin_api = _c2.get("/auth/admin/api/users").status_code
except _CfgErr:
    pass
_chef = _a2.store.get_user_by_name("chef")
r.check("...und niemand registriert sich als 'chef' zum Erst-Admin",
        (_chef is None or not _chef["is_admin"]) and _admin_api != 200,
        f"Konto={dict(_chef) if _chef else None}, Admin-API={_admin_api}")
r.check("...eine erlaubte Änderung neben admin_identifiers baut weiter",
        _nachtraeglich({"lang": "en"}, admin_identifiers=["chef"]) == ["", ""])
# (Mutationsprobe: den `_riegel`-Aufruf in _nachpruefen entfernen → rot.)

# A5: origin darf eine Liste sein — py_webauthn nimmt als expected_origin auch mehrere.
_zwei = ["https://a.example.com", "https://b.example.com"]
_f5, _w5 = _befund(passkey_enabled=True, rp_id="example.com", origin=_zwei, base_url="https://a.example.com")
r.check("A5: origin als Liste passender Origins ist kein Fehler",
        not _nennt(_f5, "origin") and not _nennt(_w5, "origin"), f"{_f5} {_w5}")
# (Mutationsprobe: in _proxies_und_passkey wieder `str(origin)` statt der Liste prüfen → rot.)
r.check("...ein schlechter Eintrag in der Liste bleibt ein Fehler",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com",
                       origin=["https://a.example.com", "https://b.example.com/pfad"])[0], "ist kein Origin"))
r.check("...ein Eintrag ausserhalb der rp_id ebenso",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com",
                       origin=["https://a.example.com", "https://a.example.org"])[0], "passt nicht"))
r.check("...eine leere Liste auch",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com", origin=[])[0], "leere Liste"))
r.check("...und base_url ausserhalb der Liste wird weiter gemeldet",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com", origin=_zwei,
                       base_url="https://c.example.com")[1], "base_url"))

# R5-1: Schema und Benutzerangabe der Login-URL kommen nicht mehr ungeprüft aus der Anfrage.
_a51, _app51 = _app(forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"],
                    cookie_secure=True)
with TestClient(_app51) as _c51:
    _l1 = _c51.get("/auth/forward", headers={"x-forwarded-proto": "http",
                                             "x-forwarded-host": "app.example.com",
                                             "x-forwarded-uri": "/x"}).headers.get("x-tinysesam-location", "")
    _l2 = _c51.get("/auth/forward", headers={"host": "127.0.0.1",
                                             "x-original-url": "http://fremd.example@app.example.com/x"}
                   ).headers.get("x-tinysesam-location", "")
r.check("R5-1: X-Forwarded-Proto: http stuft die Login-URL bei cookie_secure nicht herab",
        _l1.startswith("https://app.example.com/auth/login"), _l1)
r.check("...eine Benutzerangabe aus X-Original-URL landet nicht vor dem Host der Login-URL",
        _l2.startswith("https://app.example.com/auth/login") and "fremd.example@" not in _l2.split("?")[0],
        _l2)
_a51b, _app51b = _app(forward_auth_enabled=True, cookie_secure=False)
with TestClient(_app51b) as _c51b:
    _l3 = _c51b.get("/auth/forward", headers={"host": "127.0.0.1:8000", "x-forwarded-proto": "http"}
                    ).headers.get("x-tinysesam-location", "")
r.check("...lokal (Loopback, ohne Zertifikat) bleibt http erlaubt", _l3.startswith("http://127.0.0.1:8000/"), _l3)
# (Mutationsprobe: `_login_schema` durch das rohe Schema ersetzen → die ersten beiden rot.)
sys.exit(r.done())
