"""F1: SAML 2.0 SP — Login-Redirect, ACS→User/Session, Gruppen-Gate, Metadata.
ACS-Flow mit gefälschtem Client (keine echte signierte Assertion nötig); Metadata mit echtem onelogin."""

# Diese Suite prueft den SAML-Weg — ohne python3-saml gibt es nichts zu pruefen. Die Zusage
# steht hier und nicht im Runner: nur die Suite selbst weiss, was sie braucht.
from voraussetzung import braucht_modul  # noqa: E402
braucht_modul("onelogin", extra="saml")
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


DUMMY_CERT = "MIID...dummy...cert"   # nur nicht-leer; echte Signaturprüfung testet der Fake nicht


class FakeSAML:
    def __init__(self, nameid="alice", attrs=None, valid=True):
        self.nameid, self.attrs, self.valid = nameid, (attrs or {}), valid
        self.kontexte = []

    def login_url(self, req, base, return_to="/"):
        self.kontexte.append(req)
        return (f"https://idp.example.com/sso?SAMLRequest=abc&RelayState={return_to}",
                "_authnreq-id-4711")

    def process(self, req, base, request_id=""):
        # Die Attrappe steht für den echten Client NACH bestandener Prüfung — den Abgleich von
        # InResponseTo stellt tests/test_sicherheit_befunde.py nach. Der `req`-Satz wird
        # mitgeschrieben: Aus ihm berechnet python3-saml die eigene Adresse und vergleicht sie
        # mit der `Destination` der Assertion (F-16).
        self.kontexte.append(req)
        self.gesehene_request_id = request_id
        return {"nameid": self.nameid, "attrs": self.attrs} if self.valid else None

    def metadata(self, base):
        self.metadaten_basis = base
        return "<md:EntityDescriptor/>"


def build(**cfgkw):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(
        db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
        csrf_enabled=False, base_url=cfgkw.pop("base_url", "https://app.example.com"),
        saml_enabled=True, saml_idp_sso_url="https://idp.example.com/sso",
        saml_idp_x509cert=DUMMY_CERT, saml_attr_email="email", saml_attr_name="displayName",
        saml_attr_groups="groups", **cfgkw))
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, app


JSON = {"Accept": "application/json"}

# ---------- Login-Seite zeigt SAML-Button; /login redirectet zum IdP ----------
db, auth, app = build()
assert auth.saml is not None
c = TestClient(app)
assert ">SAML</a>" in c.get("/auth/login").text
auth.saml = FakeSAML()
r = c.get("/auth/saml/login?next=/geheim", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("https://idp.example.com/sso")
assert "RelayState=/geheim" in r.headers["location"]
ok("Login-Seite zeigt SAML-Button; /auth/saml/login → Redirect zum IdP (RelayState=next)")

# ---------- ACS: geprüfte Assertion → User anlegen + eingeloggt ----------
auth.saml = FakeSAML(nameid="alice", attrs={"email": ["alice@corp"], "displayName": ["Alice"],
                                            "groups": ["staff"]})
r = c.post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim", r.headers.get("location")
assert c.get("/geheim", headers=JSON).json() == {"u": "alice"}
u = auth.store.get_user_by_name("alice")
assert u["email"] == "alice@corp" and u["display_name"] == "Alice"
ok("ACS: gültige Assertion → lokaler User (Auto-Create, Attribute) + eingeloggt")

# ---------- ACS: ungültige Assertion → 400 ----------
c2 = TestClient(app)
auth.saml = FakeSAML(valid=False)
r = c2.post("/auth/saml/acs", data={"SAMLResponse": "x"})
assert r.status_code == 400
ok("ACS: ungültige/ungeprüfte Assertion → 400")
os.remove(db)

# ---------- Gruppen-Gate ----------
db, auth, app = build(saml_allowed_groups=["staff"])
c = TestClient(app)
auth.saml = FakeSAML(nameid="eve", attrs={"groups": ["extern"]})
r = c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
assert r.status_code == 403
ok("Gruppen-Gate: fehlende erlaubte Gruppe → 403")
os.remove(db)

# ---------- echte SP-Metadata via onelogin ----------
db, auth, app = build()
from tinysesam.saml_ import SAMLClient
md = SAMLClient(auth.cfg).metadata("https://app.example.com")
assert "EntityDescriptor" in md and "app.example.com/auth/saml/acs" in md
# über die Route
assert TestClient(app).get("/auth/saml/metadata").status_code == 200
ok("SP-Metadata (onelogin) enthält ACS-URL + ist über /auth/saml/metadata abrufbar")
os.remove(db)

# ---------- Abgelehnte Assertion: diagnostizierbar und nicht als „Link ungültig" ----------
# Beim ersten Lauf gegen einen echten IdP (Keycloak) endete eine abgelehnte Assertion in der
# Magic-Link-Fehlerseite, und der Grund stand nirgends. Beides ist jetzt Teil des Vertrags.
import io
import logging

db, auth, app = build()
auth.saml = FakeSAML(valid=False)
c = TestClient(app, headers={"Accept": "text/html"})

puffer = io.StringIO()
h = logging.StreamHandler(puffer)
seclog = logging.getLogger("tinysesam.security")
seclog.addHandler(h)
try:
    r = c.post("/auth/saml/acs", data={"SAMLResponse": "kaputt"})
finally:
    seclog.removeHandler(h)

assert r.status_code == 400, r.status_code
assert "link" not in r.text.lower(), "SAML-Fehler darf nicht als Link-Problem erscheinen"
ok("abgelehnte Assertion → 400 ohne irreführende Magic-Link-Seite")

# Der echte Client (nicht die Attrappe) schreibt den Grund ins Sicherheits-Log — ohne ihn ist eine
# fehlgeschlagene Anmeldung von aussen wie von innen nicht erklärbar.
from tinysesam.saml_ import SAMLClient


class KaputtesAuth:
    def process_response(self, request_id=None):
        pass

    def get_errors(self):
        return ["invalid_response"]

    def get_last_error_reason(self):
        return "Invalid issuer in the Assertion/Response"

    def is_authenticated(self):
        return False


client = SAMLClient(auth.cfg)
client._auth = lambda req, base: KaputtesAuth()
puffer = io.StringIO()
h = logging.StreamHandler(puffer)
seclog.addHandler(h)
try:
    assert client.process({}, "https://app.example.com") is None
finally:
    seclog.removeHandler(h)
zeile = puffer.getvalue()
assert "invalid_response" in zeile and "Invalid issuer" in zeile, zeile
ok("Grund der Ablehnung steht im Logger tinysesam.security (errors + reason)")
os.remove(db)

# ---------- F-14: eine Allowlist-ADRESSE wird über SAML nicht Erst-Admin ----------
# SAML kennt kein `email_verified`: Kein Standardattribut sagt, dass der IdP die Adresse
# geprüft hat. Ein IdP mit Selbstregistrierung (oder ein zweiter Mandant) setzte deshalb
# `email=boss@example.com` in die Assertion und war beim ersten Login Erst-Admin der Instanz —
# der Riegel aus F-14 hing allein am OIDC-Callback. Jetzt reicht die ACS ausdrücklich
# „kein Beleg" durch, und `saml` gilt als föderierter Faktor (fail-closed).
db, auth, app = build(admin_identifiers=["boss@example.com"])
auth.saml = FakeSAML(nameid="angreifer", attrs={"email": ["boss@example.com"]})
c = TestClient(app)
r = c.post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"}, follow_redirects=False)
assert r.status_code == 303, r.status_code          # die Anmeldung selbst bleibt erlaubt
u = auth.store.get_user_by_name("angreifer")
assert u is not None and not u["is_admin"], dict(u) if u else None
assert not auth.admin_exists(), "die Instanz hat jetzt einen Admin — über ein Assertion-Attribut"
ok("F-14: eine Allowlist-ADRESSE aus der Assertion befördert nicht (SAML kennt keinen Beleg)")
os.remove(db)

# Gegenprobe: Der Allowlist-NAME zählt weiterhin. Erlaubt ist er nur ohne Auto-Anlegen (sonst
# verbietet ihn der Konstruktor-Wächter) — das Konto hat der Betreiber dann selbst angelegt.
db, auth, app = build(admin_identifiers=["chefin"], saml_auto_create=False)
uid = auth.create_user("chefin", email="chefin@example.com")
auth.saml = FakeSAML(nameid="chefin", attrs={"email": ["chefin@example.com"]})
r = TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"},
                         follow_redirects=False)
assert r.status_code == 303, r.status_code
assert auth.get_user(uid)["is_admin"], "der dokumentierte Bootstrap-Weg über den Namen ist zu"
ok("... der Allowlist-NAME eines vorher angelegten Kontos befördert weiterhin")
os.remove(db)

# ---------- B-umgehung-1: der Riegel hält auch den ZWEITEN Login ----------
# Das Verweigern oben schliesst nur DIESEN Anmeldeweg. Legte die ACS das Konto mit der Vorgabe
# `email_verified=1` an, stand am Konto „belegt", obwohl die Assertion nichts belegt — und ein
# Faktor, den sich der Angreifer in seiner frisch angemeldeten Sitzung selbst einrichtet (PIN,
# Passkey), reist ohne Beleg an, liest den Vermerk und befördert doch.
db, auth, app = build(admin_identifiers=["boss@example.com"], pin_enabled=True, pin_login=True)
auth.saml = FakeSAML(nameid="mallory", attrs={"email": ["boss@example.com"]})
c = TestClient(app)
assert c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False).status_code == 303
mallory = auth.store.get_user_by_name("mallory")
assert not mallory["email_verified"], "SAML legt mit einem Beleg an, den die Assertion nie trägt"
assert c.post("/auth/pin/set", json={"pin": "246813"}).status_code == 200   # eigene Sitzung
c.get("/auth/logout")
c.cookies.clear()
r = c.post("/auth/pin", data={"username": "mallory", "pin": "246813"}, follow_redirects=False)
assert r.status_code == 303, r.status_code                   # der PIN-Login selbst geht
assert not auth.get_user(mallory["id"])["is_admin"], "Erst-Admin über den zweiten Sprung"
assert not auth.admin_exists()
ok("B-umgehung-1: ... auch ein selbst eingerichteter zweiter Faktor befördert die Adresse nicht")
os.remove(db)

# ---------- B-umgehung-10: die beiden SAML-Schlösser EINZELN gemessen ----------
# Denselben Weg sichern zwei Riegel: (1) die ACS-Route reicht ausdrücklich „kein Beleg" durch,
# (2) `saml` steht in `FOEDERIERTE_FAKTOREN` und verlangt dort ein ausdrückliches `True`.
# Solange beide stehen, fällt das Entfernen eines einzelnen nirgends auf — wer später einen
# umbaut, verliert ihn unbemerkt. Jede Probe hängt deshalb den jeweils anderen aus.

# Schloss 1 allein: `FOEDERIERTE_FAKTOREN` leer, Konto mit ECHTEM Beleg (vom Betreiber
# angelegt). Jetzt hält nur noch der Durchreicher der Route.
db, auth, app = build(admin_identifiers=["boss@example.com"])
uid = auth.create_user("angreifer", email="boss@example.com")
assert auth.store.get_user(uid)["email_verified"] == 1, "Vorbedingung: das Konto ist belegt"
auth.FOEDERIERTE_FAKTOREN = ()                 # Schloss 2 ausgehängt
auth.saml = FakeSAML(nameid="angreifer", attrs={"email": ["boss@example.com"]})
assert TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x"},
                            follow_redirects=False).status_code == 303
assert not auth.get_user(uid)["is_admin"], \
    "die ACS-Route reicht „kein Beleg\" nicht mehr durch — SAML befördert wieder"
ok("B-umgehung-10: Schloss 1 einzeln — die ACS-Route reicht „kein Beleg\" durch (ohne FOEDERIERTE_FAKTOREN)")
# Gegenprobe: Ohne den Durchreicher befördert derselbe Vermerk sofort — das misst, dass oben
# WIRKLICH die Route entschieden hat.
assert auth.maybe_promote_admin(auth.get_user(uid), faktor="saml") is True, \
    "auch ohne beide Schlösser befördert nichts — dann misst die Prüfung darüber nichts"
ok("... Gegenprobe: ohne beide Schlösser befördert der Vermerk am Konto sofort")
os.remove(db)

# Schloss 2 allein: ohne die Route, direkt an der Quelle. Ein Aufrufer, der den Beleg schlicht
# vergisst (`email_bestaetigt=None`), darf über einen föderierten Faktor nicht befördern.
db, auth, app = build(admin_identifiers=["boss@example.com"])
uid = auth.create_user("angreifer", email="boss@example.com")     # Beleg am Konto: ja
assert auth.maybe_promote_admin(auth.get_user(uid), faktor="saml") is False, \
    "der Faktor 'saml' verlangt keinen ausdrücklichen Beleg mehr"
ok("B-umgehung-10: Schloss 2 einzeln — der Faktor 'saml' befördert ohne ausdrücklichen Beleg nicht")
assert auth.maybe_promote_admin(auth.get_user(uid), email_bestaetigt=True, faktor="saml") is True, \
    "auch mit Beleg befördert der Faktor nicht — dann misst die Prüfung darüber nichts"
ok("... Gegenprobe: mit ausdrücklichem Beleg befördert derselbe Aufruf")
os.remove(db)

# ---------- R4-12: eine SAML-Identität besetzt keine lokale Kennung ----------
# Benutzername und E-Mail sind EIN Kennungs-Raum. Die Kreuzprüfung in `create_user` trifft
# auch das Auto-Anlegen aus SAML — und muss als saubere 403 ankommen, nicht als 500.
for was, nameid, attrs in (
        ("deren Adresse lokal schon Kennung ist", "eve", {"email": ["chef@example.com"]}),
        ("deren Name lokal schon Adresse ist", "chef@example.com", {"email": ["eve@example.com"]})):
    db, auth, app = build()
    lokal = auth.create_user("chef", password="lokal12345", email="chef@example.com")
    auth.saml = FakeSAML(nameid=nameid, attrs=attrs)
    r = TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
    assert r.status_code == 403, f"HTTP {r.status_code} — 303 wäre eine besetzte Kennung, 500 ein Defekt"
    assert auth.store.get_user_by_name(nameid) is None, "das Konto entstand trotz Abweisung"
    assert (auth.find_user("chef@example.com") or {})["id"] == lokal, "die Kennung wurde übernommen"
    assert any(z["event"] == "saml_ident_taken" for z in auth.store.recent_audit(20)), \
        "kein Audit-Eintrag — die Abweisung ist unsichtbar"
    ok(f"R4-12: eine SAML-Identität, {was}, legt kein Konto an (403, kein 500)")
    os.remove(db)

# Gegenprobe: freie Kennungen legen weiterhin an.
db, auth, app = build()
auth.create_user("chef", password="lokal12345", email="chef@example.com")
auth.saml = FakeSAML(nameid="neu", attrs={"email": ["neu@example.com"]})
r = TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
assert r.status_code == 303 and auth.store.get_user_by_name("neu") is not None, r.status_code
ok("... mit freien Kennungen legt SAML weiterhin an")
os.remove(db)

# ---------- F-16: die SP-Identität kommt aus base_url, nicht aus dem Host-Header ----------
# python3-saml baut aus `https`, `http_host` und `script_name` die Adresse, die es für die eigene
# hält, und vergleicht damit die `Destination` der Assertion. Kamen Schema und Host aus
# X-Forwarded-Proto/Host, bestimmte der Anfragende diesen Vergleich mit: Er legte eine Assertion
# vor, deren Destination auf SEINEN Namen lautet, und setzte den Header passend dazu. Zusammen
# mit der Bindung über den blossen Benutzernamen (F-11) war das eine Kontoübernahme.
db16, auth16, app16 = build()
auth16.saml = FakeSAML()
c16 = TestClient(app16)
FREMD = {"X-Forwarded-Proto": "http", "X-Forwarded-Host": "angreifer.example",
         "Host": "angreifer.example"}

auth16.saml.kontexte.clear()
c16.get("/auth/saml/login", headers=FREMD, follow_redirects=False)
_k = auth16.saml.kontexte[-1]
assert _k["http_host"] == "app.example.com", f"fremder Host im SAML-Kontext: {_k}"
assert _k["https"] == "on", _k
ok("F-16: der AuthnRequest nennt den Host aus base_url, nicht den aus dem Header")

auth16.saml.kontexte.clear()
c16.post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"}, headers=FREMD,
         follow_redirects=False)
_k = auth16.saml.kontexte[-1]
assert _k["http_host"] == "app.example.com", f"fremder Host an der ACS: {_k}"
ok("F-16: …und die ACS rechnet ihre eigene Adresse genauso aus")

# Die Metadaten bauen Entity-ID und ACS-URL — sie kommen aus derselben geprüften Basis, sonst
# läge im Dokument, das der IdP einliest, der Name des Anfragenden.
c16.get("/auth/saml/metadata", headers=FREMD)
assert auth16.saml.metadaten_basis == "https://app.example.com", auth16.saml.metadaten_basis
ok("F-16: …auch die Metadaten, die der IdP einliest")

# Der Pfadanteil einer unter einem Unterpfad montierten App gehört mit in die Selbst-Adresse,
# sonst weicht sie von der ACS-URL in den Settings ab und die Destination-Prüfung scheitert.
db16b, auth16b, app16b = build(base_url="https://app.example.com/sso")
auth16b.saml = FakeSAML()
c16b = TestClient(app16b)
auth16b.saml.kontexte.clear()
c16b.get("/auth/saml/login", follow_redirects=False)
_kb = auth16b.saml.kontexte[-1]
assert _kb["script_name"] == "/sso/auth/saml/login", _kb
ok("F-16: der Unterpfad aus base_url steht in der berechneten Selbst-Adresse")

# Und er wird nicht doppelt angehängt, wenn er im Pfad schon steckt (ASGI-Mount).
from tinysesam.saml_ import request_kontext                                # noqa: E402
_direkt = request_kontext("https://app.example.com/sso", "/sso/auth/saml/acs")
assert _direkt["script_name"] == "/sso/auth/saml/acs", _direkt
ok("F-16: …und nicht doppelt, wenn er schon im Pfad steht")

for _d in (db16, db16b):
    os.remove(_d)

# ---------- F-11: die NameID bindet, nicht der Name ----------
# Bei SAML ist die stabile Kennung die NameID (oder ein Attribut, wenn der IdP transiente
# NameIDs schickt). Ohne sie hing die Zuordnung am Benutzernamen aus einem Attribut — und wer
# den im Verzeichnis ändert, bekam ein fremdes lokales Konto.
db11, auth11, app11 = build(saml_attr_username="uid")
c11 = TestClient(app11)


def _saml_anmelden(auth, app, nameid, attrs):
    auth.saml = FakeSAML(nameid=nameid, attrs=attrs)
    return TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"},
                                follow_redirects=False)


# (1) Neues Konto wird an die NameID gebunden.
assert _saml_anmelden(auth11, app11, "nid-alice", {"uid": ["alice"]}).status_code == 303
_uid_a = auth11.store.get_user_by_name("alice")["id"]
assert auth11.store.get_federated_kennung("saml", _uid_a) == "nid-alice"
ok("F-11: ein über SAML angelegtes Konto wird an die NameID gebunden")

# (2) Der IdP nennt denselben Menschen anders — dieselbe NameID, dasselbe Konto.
assert _saml_anmelden(auth11, app11, "nid-alice", {"uid": ["alice.neu"]}).status_code == 303
assert auth11.store.get_user_by_name("alice.neu") is None, "es entstand ein zweites Konto"
ok("F-11: ein neuer Name bei gleicher NameID führt in dasselbe Konto")

# (3) Der Angriff: fremde NameID unter dem alten Namen.
_r = _saml_anmelden(auth11, app11, "nid-FREMD", {"uid": ["alice"]})
assert _r.status_code == 403, f"HTTP {_r.status_code} — das fremde Konto kam durch"
assert any(e["event"] == "saml_kennung_wechsel" for e in auth11.store.recent_audit(limit=10))
ok("F-11: eine fremde NameID unter altem Namen wird abgewiesen")

# (4) `saml_attr_id`: Wenn der IdP transiente NameIDs schickt, bindet ein Attribut.
db11b, auth11b, app11b = build(saml_attr_username="uid", saml_attr_id="employeeNumber")
assert _saml_anmelden(auth11b, app11b, "transient-4711",
                      {"uid": ["bob"], "employeeNumber": ["p-0815"]}).status_code == 303
_uid_b = auth11b.store.get_user_by_name("bob")["id"]
assert auth11b.store.get_federated_kennung("saml", _uid_b) == "p-0815", \
    "die transiente NameID wurde gebunden statt des Attributs"
# Beim nächsten Login ist die NameID eine andere — das Attribut bleibt.
assert _saml_anmelden(auth11b, app11b, "transient-9999",
                      {"uid": ["bob"], "employeeNumber": ["p-0815"]}).status_code == 303
assert auth11b.store.get_user_by_name("bob")["id"] == _uid_b
ok("F-11: saml_attr_id bindet das Attribut — eine transiente NameID wechselt bei jedem Login")

for _d in (db11, db11b):
    os.remove(_d)

# ---------- F-22: die ACS ist ratenbegrenzt, und jede Abweisung steht im Audit-Log ----------
# Bis 0.20.0 war die ACS die einzige Anmelderoute ohne Drossel — und die teuerste: Jeder POST geht
# durch die XML-Signaturprüfung. Fachliche Abweisungen (Gruppe, kein Konto, gesperrt) endeten
# stumm in einer 403; „ich komme nicht rein" war serverseitig nicht zu beantworten.
db22, auth22, app22 = build(saml_allowed_groups=["staff"])
auth22.set_security("rate_limit_max", 3)
c22 = TestClient(app22)
auth22.saml = FakeSAML(nameid="eve", attrs={"groups": ["extern"]})
_antw22 = [c22.post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False).status_code
           for _ in range(5)]
assert _antw22[:3] == [403, 403, 403] and _antw22[3:] == [429, 429], _antw22
ok("F-22: die ACS ist ratenbegrenzt (nach rate_limit_max → 429, vor der Signaturprüfung)")
_z22 = auth22.store.recent_audit(50)
assert any(z["event"] == "saml_denied" and z["username"] == "eve" and "grund=gruppe" in (z["detail"] or "")
           and z["ip"] for z in _z22), [dict(z) for z in _z22][:5]
ok("F-22: Gruppen-Abweisung → Audit-Zeile saml_denied mit Grund und IP")
os.remove(db22)

db22b, auth22b, app22b = build(saml_auto_create=False)
auth22b.saml = FakeSAML(nameid="unbekannt", attrs={})
assert TestClient(app22b).post("/auth/saml/acs", data={"SAMLResponse": "x"},
                               follow_redirects=False).status_code == 403
assert any(z["event"] == "saml_denied" and "grund=kein_konto" in (z["detail"] or "")
           for z in auth22b.store.recent_audit(20))
_uid22 = auth22b.create_user("gesperrt")
auth22b.store._exec("UPDATE users SET disabled=1 WHERE id=?", (_uid22,))
auth22b.saml = FakeSAML(nameid="gesperrt", attrs={})
assert TestClient(app22b).post("/auth/saml/acs", data={"SAMLResponse": "x"},
                               follow_redirects=False).status_code == 403
assert any(z["event"] == "saml_denied" and z["username"] == "gesperrt"
           and "grund=konto_gesperrt" in (z["detail"] or "") for z in auth22b.store.recent_audit(20))
auth22b.saml = FakeSAML(valid=False)
assert TestClient(app22b).post("/auth/saml/acs", data={"SAMLResponse": "x"}).status_code == 400
assert any(z["event"] == "saml_invalid" for z in auth22b.store.recent_audit(20))
ok("F-22: kein Konto, gesperrtes Konto und abgelehnte Assertion hinterlassen je eine Audit-Zeile")
os.remove(db22b)

# ---------- F-21: SHA-1 in Signatur oder Digest wird abgewiesen ----------
# Gemessen gegen ECHTES python3-saml mit einer echt signierten Assertion: Nur so ist belegt, dass
# der Schalter in den Settings auch dort ankommt, wo die Signatur geprüft wird.
from onelogin.saml2.settings import OneLogin_Saml2_Settings  # noqa: E402
from tinysesam.saml_ import SAMLClient, request_kontext       # noqa: E402

_cfg21 = TinySesamConfig(db_path=":memory:", saml_enabled=True, passkey_enabled=False,
                         saml_idp_sso_url="https://idp.example.com/sso",
                         saml_idp_x509cert=DUMMY_CERT, base_url="https://app.example.com")
_st21 = OneLogin_Saml2_Settings(SAMLClient(_cfg21).settings("https://app.example.com"),
                                sp_validation_only=True)
assert _st21.get_security_data().get("rejectDeprecatedAlgorithm") is True, _st21.get_security_data()
ok("F-21: rejectDeprecatedAlgorithm ist in den wirksamen python3-saml-Settings gesetzt")

import importlib.util as _ilu21  # noqa: E402
if _ilu21.find_spec("cryptography") and _ilu21.find_spec("lxml"):
    import base64 as _b64
    import datetime as _dt
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from lxml import etree as _etree
    from onelogin.saml2.utils import OneLogin_Saml2_Utils as _Utils
    from onelogin.saml2.constants import OneLogin_Saml2_Constants as _K

    _schluessel = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _jetzt = _dt.datetime.now(_dt.timezone.utc)
    _name = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "idp.example.com")])
    _zert = (_x509.CertificateBuilder().subject_name(_name).issuer_name(_name)
             .public_key(_schluessel.public_key()).serial_number(1)
             .not_valid_before(_jetzt - _dt.timedelta(days=1))
             .not_valid_after(_jetzt + _dt.timedelta(days=30)).sign(_schluessel, _hashes.SHA256()))
    _key_pem = _schluessel.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                                         _ser.NoEncryption()).decode()
    _zert_pem = _zert.public_bytes(_ser.Encoding.PEM).decode()
    _BASIS, _IDP = "https://app.example.com", "https://idp.example.com/sso"
    _ACS, _SP = _BASIS + "/auth/saml/acs", _BASIS + "/auth/saml/metadata"

    def _signierte_antwort(sig, dig, rid="_req-21"):
        vor = (_jetzt - _dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        nach = (_jetzt + _dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r21" Version="2.0" '
            f'IssueInstant="{vor}" Destination="{_ACS}" InResponseTo="{rid}">'
            f'<saml:Issuer>{_IDP}</saml:Issuer><samlp:Status><samlp:StatusCode '
            'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            f'<saml:Assertion ID="_a21" Version="2.0" IssueInstant="{vor}"><saml:Issuer>{_IDP}</saml:Issuer>'
            '<saml:Subject><saml:NameID>alice</saml:NameID><saml:SubjectConfirmation '
            'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData '
            f'NotOnOrAfter="{nach}" Recipient="{_ACS}" InResponseTo="{rid}"/></saml:SubjectConfirmation>'
            f'</saml:Subject><saml:Conditions NotBefore="{vor}" NotOnOrAfter="{nach}">'
            f'<saml:AudienceRestriction><saml:Audience>{_SP}</saml:Audience></saml:AudienceRestriction>'
            f'</saml:Conditions><saml:AuthnStatement AuthnInstant="{vor}" SessionIndex="_s21">'
            '<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:'
            'Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
            '<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>'
            'alice@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
            '</saml:Assertion></samlp:Response>')
        dok = _etree.fromstring(xml.encode())
        behauptung = dok.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        dok.replace(behauptung, _etree.fromstring(_Utils.add_sign(
            _etree.tostring(behauptung), _key_pem, _zert_pem, sign_algorithm=sig, digest_algorithm=dig)))
        return _b64.b64encode(_etree.tostring(dok)).decode()

    _echt21 = SAMLClient(TinySesamConfig(
        db_path=":memory:", saml_enabled=True, passkey_enabled=False, saml_idp_sso_url=_IDP,
        saml_idp_x509cert="".join(_zert_pem.strip().splitlines()[1:-1]), base_url=_BASIS))

    def _pruefe21(sig, dig):
        req = request_kontext(_BASIS, "/auth/saml/acs", form={"SAMLResponse": _signierte_antwort(sig, dig)})
        return _echt21.process(req, _BASIS, request_id="_req-21")

    _gut21 = _pruefe21(_K.RSA_SHA256, _K.SHA256)
    assert _gut21 and _gut21["nameid"] == "alice", \
        f"Vorbedingung: eine SHA-256-signierte Assertion muss durchgehen, sonst misst der Rest nichts: {_gut21}"
    assert _pruefe21(_K.RSA_SHA1, _K.SHA1) is None, "rsa-sha1 + sha1 wurde angenommen"
    assert _pruefe21(_K.RSA_SHA1, _K.SHA256) is None, "rsa-sha1 als Signaturverfahren wurde angenommen"
    assert _pruefe21(_K.RSA_SHA256, _K.SHA1) is None, "sha1 als Digest wurde angenommen"
    ok("F-21: echt signierte Assertion — SHA-256 geht durch, SHA-1 in Signatur ODER Digest nicht")
else:                                                    # pragma: no cover
    print("  – F-21 gegen eine echt signierte Assertion nicht gefahren (cryptography/lxml fehlen); "
          "gemessen ist oben nur der Settings-Schalter")

print("\nSAML OK ✅")
