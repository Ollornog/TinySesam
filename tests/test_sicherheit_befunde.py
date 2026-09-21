"""Nachgestellte Angriffe aus der Reifeprüfung vom 2026-09-21.

Jede Prüfung hier hält einen Angriff fest, der einmal funktioniert hat. Sie sind bewusst nach dem
ANGRIFF benannt, nicht nach der Funktion — wer eine davon rot sieht, soll sofort wissen, was
wieder möglich ist.

Alles läuft auf Vorgabewerten. Ein Fund, der nur unter einer Konfiguration auftritt, die niemand
wählt, wäre keiner gewesen.
"""
from __future__ import annotations

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

sys.exit(r.done())
