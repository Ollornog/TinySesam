"""Batch B: LDAP/lldap-Backend — Login gegen Verzeichnis, Auto-Create, Gruppen-Gate.
Nutzt einen gefälschten LDAP-Client (kein Server/ldap3 nötig) und testet die Integration."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


class FakeLDAP:
    def __init__(self, users):
        self.users = users   # {username: {"password","email","name","groups"}}

    def authenticate(self, username, password):
        u = self.users.get(username)
        if not u or u["password"] != password:
            return None
        return {"username": username, "email": u.get("email"),
                "name": u.get("name", username), "groups": u.get("groups", []),
                "id": u.get("id")}   # stabile Kennung des Verzeichnisses (F-11)


def build(**cfgkw):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    # `ldap_allow_plaintext=True`: Diese Suite spricht mit einer Attrappe, es gibt weder Server
    # noch Netz. Seit F-12 wäre `ldap://` ohne TLS sonst ein Aufbaufehler — zu Recht, aber hier
    # ginge es an der Sache vorbei. Der Riegel selbst wird unten eigens gemessen.
    cfgkw.setdefault("ldap_allow_plaintext", True)
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False, ldap_enabled=True, ldap_url="ldap://dummy", **cfgkw))
    auth.ensure_admin("admin", "lokalpw")   # lokaler User mit lokalem Passwort
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, TestClient(app)


JSON = {"Accept": "application/json"}

# ---------- LDAP-User ohne lokales Passwort → Login + Auto-Create ----------
db, auth, c = build()
auth.ldap = FakeLDAP({"alice": {"password": "ldappw", "email": "alice@corp", "name": "Alice",
                                "groups": ["cn=staff,ou=groups,dc=corp"]}})
assert auth.store.get_user_by_name("alice") is None
r = c.post("/auth/login", data={"username": "alice", "password": "ldappw", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303, r.status_code
assert c.get("/geheim", headers=JSON).json() == {"u": "alice"}
u = auth.store.get_user_by_name("alice")
assert u and u["email"] == "alice@corp" and u["display_name"] == "Alice"
ok("LDAP-Login legt lokalen User automatisch an (E-Mail/Name übernommen)")

# falsches LDAP-Passwort → 401
c.get("/auth/logout")
assert c.post("/auth/login", data={"username": "alice", "password": "falsch"}).status_code == 401
ok("falsches LDAP-Passwort → 401")
os.remove(db)

# ---------- lokales Passwort funktioniert weiter neben LDAP ----------
db, auth, c = build()
auth.ldap = FakeLDAP({})
r = c.post("/auth/login", data={"username": "admin", "password": "lokalpw", "next": "/"}, follow_redirects=False)
assert r.status_code == 303
ok("lokaler Passwort-Login funktioniert weiterhin (LDAP nur Fallback)")
os.remove(db)

# ---------- Gruppen-Gate ----------
db, auth, c = build(ldap_allowed_groups=["staff"])
auth.ldap = FakeLDAP({
    "bob": {"password": "x", "groups": ["cn=staff,ou=groups,dc=corp"]},      # erlaubt
    "eve": {"password": "x", "groups": ["cn=extern,ou=groups,dc=corp"]},     # nicht erlaubt
})
assert c.post("/auth/login", data={"username": "eve", "password": "x"}).status_code == 401
ok("Gruppen-Gate: User ohne erlaubte Gruppe → 401")
c.get("/auth/logout")
r = c.post("/auth/login", data={"username": "bob", "password": "x", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and c.get("/geheim", headers=JSON).json() == {"u": "bob"}
ok("Gruppen-Gate: User mit erlaubter Gruppe → Login")
os.remove(db)

# ---------- auto_create=False → kein lokaler User, kein Login ----------
db, auth, c = build(ldap_auto_create=False)
auth.ldap = FakeLDAP({"carol": {"password": "x"}})
assert c.post("/auth/login", data={"username": "carol", "password": "x"}).status_code == 401
ok("ldap_auto_create=False: unbekannter LDAP-User wird nicht angelegt")
os.remove(db)

# ---------- F-14: eine Allowlist-ADRESSE wird über LDAP nicht Erst-Admin ----------
# Das `mail`-Attribut pflegt in vielen Verzeichnissen der Nutzer selbst, und einen Beleg wie
# OIDCs Claim `email_verified` kennt LDAP nicht. Wer sich dort die Admin-Adresse eintrug, war
# beim ersten Login Erst-Admin der Instanz: Der Riegel aus F-14 hing allein am OIDC-Callback,
# die Login-Route rief `apply_factor` ohne Beleg, und „kein Beleg" (None) hiess dort
# „kein IdP im Spiel". Jetzt reicht die Route ausdrücklich „kein Beleg" durch (fail-closed).
def baue_ohne_admin(**cfgkw):
    """Wie `build`, aber OHNE `ensure_admin` — die Bootstrap-Wege greifen nur, solange es
    keinen Admin gibt. Mit dem lokalen Admin aus `build` würde jede Prüfung hier grün sein,
    ohne etwas zu messen."""
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test",
                                     passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False, ldap_enabled=True,
                                     ldap_url="ldap://dummy", ldap_allow_plaintext=True, **cfgkw))
    app = FastAPI()
    app.include_router(auth.router())
    return db, auth, TestClient(app)


db, auth, c = baue_ohne_admin(admin_identifiers=["boss@example.com"])
auth.ldap = FakeLDAP({"angreifer": {"password": "x", "email": "boss@example.com", "groups": []}})
r = c.post("/auth/login", data={"username": "angreifer", "password": "x"}, follow_redirects=False)
assert r.status_code == 303, r.status_code          # die Anmeldung selbst bleibt erlaubt
u = auth.store.get_user_by_name("angreifer")
assert u is not None and not u["is_admin"], dict(u) if u else None
assert not auth.admin_exists(), "die Instanz hat jetzt einen Admin — über ein mail-Attribut"
ok("F-14: eine Allowlist-ADRESSE aus dem Verzeichnis befördert nicht (LDAP kennt keinen Beleg)")
os.remove(db)

# Gegenprobe, sonst wäre die Prüfung oben auch grün, wenn der Bootstrap komplett kaputt wäre:
# Ein Allowlist-NAME zählt weiterhin. Erlaubt ist er nur ohne Auto-Anlegen (sonst verbietet ihn
# der Konstruktor-Wächter) — das Konto hat der Betreiber dann selbst angelegt.
db, auth, c = baue_ohne_admin(admin_identifiers=["chefin"], ldap_auto_create=False)
uid = auth.create_user("chefin", email="chefin@example.com")
auth.ldap = FakeLDAP({"chefin": {"password": "x", "email": "chefin@example.com", "groups": []}})
r = c.post("/auth/login", data={"username": "chefin", "password": "x"}, follow_redirects=False)
assert r.status_code == 303, r.status_code
assert auth.get_user(uid)["is_admin"], "der dokumentierte Bootstrap-Weg über den Namen ist zu"
ok("... der Allowlist-NAME eines vorher angelegten Kontos befördert weiterhin")
os.remove(db)

# ---------- B-umgehung-1: der Riegel hält auch den ZWEITEN Login ----------
# Das Verweigern oben schliesst nur DIESEN Anmeldeweg. Legte LDAP das Konto mit der Vorgabe
# `email_verified=1` an, stand am Konto „belegt", obwohl nichts belegt wurde — und der nächste
# Faktor, den sich der Angreifer in seiner frisch angemeldeten Sitzung selbst einrichtet (PIN,
# Passkey: Selbstbedienung), reist ohne Beleg an, liest den Vermerk und befördert doch. Der
# Bootstrap-Angriff war damit unverändert möglich, nur mit einem Klick mehr.
db, auth, c = baue_ohne_admin(admin_identifiers=["boss@example.com"],
                              pin_enabled=True, pin_login=True)
auth.ldap = FakeLDAP({"mallory": {"password": "x", "email": "boss@example.com", "groups": []}})
assert c.post("/auth/login", data={"username": "mallory", "password": "x"},
              follow_redirects=False).status_code == 303
mallory = auth.store.get_user_by_name("mallory")
assert not mallory["email_verified"], "LDAP legt mit einem Beleg an, den niemand erbracht hat"
assert c.post("/auth/pin/set", json={"pin": "246813"}).status_code == 200   # eigene Sitzung
c.get("/auth/logout")
c.cookies.clear()
r = c.post("/auth/pin", data={"username": "mallory", "pin": "246813"}, follow_redirects=False)
assert r.status_code == 303, r.status_code                   # der PIN-Login selbst geht
assert not auth.get_user(mallory["id"])["is_admin"], "Erst-Admin über den zweiten Sprung"
assert not auth.admin_exists()
ok("B-umgehung-1: ... auch ein selbst eingerichteter zweiter Faktor befördert die Adresse nicht")
os.remove(db)

# Gegenprobe: Derselbe zweite Sprung mit einem Konto, dessen Adresse jemand verbürgt hat (hier
# der Betreiber beim Anlegen), befördert weiterhin — sonst wäre oben auch eine komplett kaputte
# PIN-Beförderung grün.
db, auth, c = baue_ohne_admin(admin_identifiers=["boss@example.com"], ldap_auto_create=False,
                              pin_enabled=True, pin_login=True)
uid = auth.create_user("chefin", password="lokal12345", email="boss@example.com")
assert c.post("/auth/login", data={"username": "chefin", "password": "lokal12345"},
              follow_redirects=False).status_code == 303
assert auth.get_user(uid)["is_admin"], "der belegte Weg ist zu"
ok("... die belegte Adresse eines lokal angelegten Kontos befördert weiterhin")
os.remove(db)

# ---------- B-umgehung-10: das Schloss der LOGIN-ROUTE einzeln gemessen ----------
# Zwei Schlösser sichern denselben Weg: (1) die Route reicht ausdrücklich „kein Beleg" durch,
# (2) ein aus dem Verzeichnis angelegtes Konto trägt gar keinen Beleg. Solange beide stehen,
# fällt das Entfernen von (1) nirgends auf — wer den Durchreicher später umbaut, verliert ihn
# unbemerkt. Deshalb hier ein Konto, das einen ECHTEN Beleg trägt (der Betreiber hat es
# angelegt) und dessen Namen das Verzeichnis kennt: Jetzt hängt alles an (1).
db, auth, c = baue_ohne_admin(admin_identifiers=["boss@example.com"], ldap_auto_create=False)
uid = auth.create_user("chefin", email="boss@example.com")       # Beleg am Konto: ja
assert auth.store.get_user(uid)["email_verified"] == 1, "Vorbedingung: das Konto ist belegt"
auth.ldap = FakeLDAP({"chefin": {"password": "x", "email": "boss@example.com", "groups": []}})
assert c.post("/auth/login", data={"username": "chefin", "password": "x"},
              follow_redirects=False).status_code == 303        # Login über das Verzeichnis
assert not auth.get_user(uid)["is_admin"], \
    "die Login-Route reicht „kein Beleg\" nicht mehr durch — LDAP befördert wieder"
ok("B-umgehung-10: Schloss 1 einzeln — die Login-Route reicht „kein Beleg\" durch, auch bei belegtem Konto")
# Gegenprobe: Ohne diesen Durchreicher (`email_bestaetigt=None`) befördert derselbe Vermerk
# sofort — das misst, dass oben WIRKLICH die Route entschieden hat und nicht etwas anderes.
assert auth.maybe_promote_admin(auth.get_user(uid), faktor="password") is True, \
    "auch ohne den Durchreicher befördert nichts — dann misst die Prüfung darüber nichts"
ok("... Gegenprobe: ohne den Durchreicher befördert der Vermerk am Konto sofort")
os.remove(db)

# ---------- R4-12: eine Verzeichnis-Kennung besetzt keine lokale ----------
# Benutzername und E-Mail sind EIN Kennungs-Raum (`find_user` sucht in beiden Spalten). Die
# Kreuzprüfung sitzt in `create_user` und trifft damit auch das Auto-Anlegen aus LDAP — und
# sie muss hier als saubere Abweisung ankommen, nicht als 500 mitten im Anmeldevorgang.
for was, verzeichnis, kennung in (
        ("deren Adresse lokal schon Kennung ist", {"password": "x", "email": "chef@example.com"}, "eve"),
        ("deren Name lokal schon Adresse ist", {"password": "x", "email": "eve@example.com"}, "chef@example.com")):
    db, auth, c = baue_ohne_admin()
    lokal = auth.create_user("chef", password="lokal12345", email="chef@example.com")
    auth.ldap = FakeLDAP({kennung: dict(verzeichnis, groups=[])})
    r = c.post("/auth/login", data={"username": kennung, "password": "x"}, follow_redirects=False)
    assert r.status_code == 401, f"HTTP {r.status_code} — 303 wäre eine besetzte Kennung, 500 ein Defekt"
    assert auth.store.get_user_by_name(kennung) is None, "das Konto entstand trotz Abweisung"
    assert (auth.find_user("chef@example.com") or {})["id"] == lokal, "die Kennung wurde übernommen"
    assert any(z["event"] == "ldap_ident_taken" for z in auth.store.recent_audit(20)), \
        "kein Audit-Eintrag — die Abweisung ist unsichtbar"
    ok(f"R4-12: eine Verzeichnis-Identität, {was}, legt kein Konto an (401, kein 500)")
    os.remove(db)

# Gegenprobe: freie Kennungen legen weiterhin an.
db, auth, c = baue_ohne_admin()
auth.create_user("chef", password="lokal12345", email="chef@example.com")
auth.ldap = FakeLDAP({"neu": {"password": "x", "email": "neu@example.com", "groups": []}})
r = c.post("/auth/login", data={"username": "neu", "password": "x"}, follow_redirects=False)
assert r.status_code == 303 and auth.store.get_user_by_name("neu") is not None, r.status_code
ok("... mit freien Kennungen legt LDAP weiterhin an")
os.remove(db)

# ---------- F-28: Verweisen (Referrals) wird nie gefolgt ----------
# ldap3 folgt einem `SearchResultDone resultCode=10 (referral)` von sich aus und bindet auf dem
# Host, den die ANTWORT nennt, erneut mit denselben Zugangsdaten. Ein übernommenes Verzeichnis
# — oder auf einer Klartext-Verbindung jeder Zwischenhörer — bekam damit DN und Passwort des
# Dienstkontos bzw. das Passwort des Anmeldenden frei Haus geliefert. Nachgestellt wird das mit
# zwei echten LDAP-Servern auf Loopback: A ist das konfigurierte Verzeichnis und antwortet mit
# einem Verweis auf B, B schreibt mit, was bei ihm ankommt.
import importlib.util, socket, sys, threading, time, types
from tinysesam.ldap_ import LDAPClient

SVC_DN, SVC_PW = "cn=svc,ou=services,dc=example,dc=com", "DIENST-GEHEIM-123"


def tlv(tag, inhalt):
    n = len(inhalt)
    if n < 0x80:
        laenge = bytes([n])
    else:
        roh = n.to_bytes((n.bit_length() + 7) // 8, "big")
        laenge = bytes([0x80 | len(roh)]) + roh
    return bytes([tag]) + laenge + inhalt


def zerlegen(daten):
    """(messageID, protocolOp-Tag) aus einer LDAPMessage lesen."""
    i = 1
    if daten[i] & 0x80:
        i += 1 + (daten[i] & 0x7F)
    else:
        i += 1
    assert daten[i] == 0x02, "kein INTEGER an der erwarteten Stelle"
    n = daten[i + 1]
    mid = int.from_bytes(daten[i + 2:i + 2 + n], "big")
    return mid, daten[i + 2 + n]


def antwort(mid, op_tag, inhalt):
    return tlv(0x30, tlv(0x02, mid.to_bytes(1, "big")) + tlv(op_tag, inhalt))


def bind_ok(mid):
    return antwort(mid, 0x61, tlv(0x0A, b"\x00") + tlv(0x04, b"") + tlv(0x04, b""))


def suche_fertig(mid, uri=None):
    """SearchResultDone — mit Verweis (resultCode 10) oder schlicht erfolgreich (0)."""
    kopf = tlv(0x0A, b"\x0a" if uri else b"\x00") + tlv(0x04, b"") + tlv(0x04, b"")
    return antwort(mid, 0x65, kopf + (tlv(0xA3, tlv(0x04, uri)) if uri else b""))


def lauscher():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(4)
    s.settimeout(10)
    return s, s.getsockname()[1]


def verzeichnis(sock, verweis_uri, gesehen):
    """Server A: Bind annehmen, Suche mit/ohne Verweis beantworten."""
    try:
        conn, _ = sock.accept()
        conn.settimeout(8)
        while True:
            daten = conn.recv(8192)
            if not daten:
                break
            mid, op = zerlegen(daten)
            gesehen.append(hex(op))
            if op == 0x60:
                conn.sendall(bind_ok(mid))
            elif op == 0x63:
                conn.sendall(suche_fertig(mid, verweis_uri))
            else:                                  # Unbind o.a. → Schluss
                break
        conn.close()
    except Exception as e:
        gesehen.append(f"fehler: {e!r}")


def fremder_host(sock, eimer):
    """Server B: nur mitschreiben, was hereinkommt."""
    try:
        conn, _ = sock.accept()
        conn.settimeout(8)
        eimer.append(conn.recv(8192))
        conn.close()
    except Exception:
        eimer.append(b"")


def aufbau(verweis=True):
    """Beide Server starten; gibt (port_a, gesehen_a, eimer_b, sockets) zurück."""
    sa, pa = lauscher()
    sb, pb = lauscher()
    gesehen, eimer = [], []
    uri = (f"ldap://127.0.0.1:{pb}/ou=people,dc=example,dc=com??sub?(objectClass=*)".encode()
           if verweis else None)
    threading.Thread(target=verzeichnis, args=(sa, uri, gesehen), daemon=True).start()
    threading.Thread(target=fremder_host, args=(sb, eimer), daemon=True).start()
    time.sleep(0.2)
    return pa, gesehen, eimer, (sa, sb)


HAT_LDAP3 = importlib.util.find_spec("ldap3") is not None

if HAT_LDAP3:
    # (a) Such-Bind des Dienstkontos: A verweist auf B → bei B darf NICHTS ankommen.
    pa, gesehen, eimer, socks = aufbau()
    cfg_svc = TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True,
        ldap_url=f"ldap://127.0.0.1:{pa}", ldap_bind_dn=SVC_DN, ldap_bind_password=SVC_PW,
        ldap_user_base="ou=people,dc=example,dc=com", ldap_user_filter="(uid={username})")
    # Dabei gleich mitmessen, dass der verworfene Verweis eine Logzeile schreibt — hier gegen
    # ein ECHTES ldap3, nicht gegen den Stub weiter unten (nur so ist belegt, dass der Verweis
    # wirklich in `Connection.result` steht und nicht bloss in unserer Annahme davon).
    import io as _io2, logging as _logging2
    from tinysesam.security import seclog as _seclog2
    _puffer = _io2.StringIO()
    _haken = _logging2.StreamHandler(_puffer)
    _seclog2.addHandler(_haken)
    try:
        assert LDAPClient(cfg_svc).authenticate("alice", "egal") is None
    finally:
        _seclog2.removeHandler(_haken)
    assert "VERWEIS" in _puffer.getvalue() and "Global Catalog" in _puffer.getvalue(), \
        f"echtes ldap3: der verworfene Verweis blieb stumm: {_puffer.getvalue()[:200]!r}"
    time.sleep(0.5)
    beute = eimer[0] if eimer else b""
    assert SVC_DN.encode() not in beute, f"Bind-DN des Dienstkontos ging an den Verweis-Host: {beute[:120]!r}"
    assert SVC_PW.encode() not in beute, f"Passwort des Dienstkontos ging an den Verweis-Host: {beute[:120]!r}"
    assert beute == b"", f"der Verweis-Host wurde überhaupt kontaktiert: {beute[:120]!r}"
    for s in socks:
        s.close()
    ok("Verweis beim Such-Bind: Dienstkonto-Zugangsdaten erreichen den fremden Host nicht")

    # (b) Benutzer-Bind (Direkt-DN): der Verweis kommt auf die Attribut-Suche, die auf der
    #     Verbindung mit dem PASSWORT DES ANMELDENDEN läuft.
    pa, gesehen, eimer, socks = aufbau()
    cfg_usr = TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True,
        ldap_url=f"ldap://127.0.0.1:{pa}",
        ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com")
    _puffer_b = _io2.StringIO()
    _haken_b = _logging2.StreamHandler(_puffer_b)
    _seclog2.addHandler(_haken_b)
    try:
        info = LDAPClient(cfg_usr).authenticate("alice", "NUTZER-GEHEIM-456")
    finally:
        _seclog2.removeHandler(_haken_b)
    # Auch auf diesem Weg darf der Verweis nicht stumm bleiben: Ohne die Attribute fehlen
    # E-Mail, Name und Gruppen — mit `ldap_allowed_groups` ist das eine Abweisung ohne Grund.
    assert "Attribut-Suche" in _puffer_b.getvalue(), \
        f"der Verweis auf der Attribut-Suche blieb stumm: {_puffer_b.getvalue()[:200]!r}"
    time.sleep(0.5)
    beute = eimer[0] if eimer else b""
    assert b"NUTZER-GEHEIM-456" not in beute, f"Nutzerpasswort ging an den Verweis-Host: {beute[:120]!r}"
    assert beute == b"", f"der Verweis-Host wurde überhaupt kontaktiert: {beute[:120]!r}"
    assert info and info["username"] == "alice"   # der Bind hat das Passwort bestätigt
    for s in socks:
        s.close()
    ok("Verweis bei der Attribut-Suche: das Passwort des Anmeldenden bleibt beim Verzeichnis")

    # (c) Gegenprobe ohne Verweis: der normale Weg funktioniert unverändert.
    pa, gesehen, eimer, socks = aufbau(verweis=False)
    cfg_ok = TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True,
        ldap_url=f"ldap://127.0.0.1:{pa}",
        ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com")
    info = LDAPClient(cfg_ok).authenticate("alice", "richtig")
    assert info and info["username"] == "alice" and info["name"] == "alice", info
    assert "0x60" in gesehen and "0x63" in gesehen, gesehen   # Bind UND Suche liefen wirklich
    for s in socks:
        s.close()
    ok("ohne Verweis: Bind + Attribut-Suche gegen einen echten Server laufen weiter durch")
else:                                              # pragma: no cover
    print("  – Verweis-Test gegen echte Server übersprungen (ldap3 fehlt)")

# Die Zusage selbst — unabhängig davon, ob das Extra installiert ist: JEDE Verbindung, die
# dieses Modul aufmacht, schaltet die Verweis-Verfolgung ab, und der Server erlaubt keinen
# Verweis-Host. Gemessen mit einem untergeschobenen ldap3: Fällt einer der beiden Parameter
# weg, ist diese Prüfung rot, auch wenn kein Verzeichnis in der Nähe ist.
def stub_ldap3(mitschrift, leer=False, result=None):
    """Untergeschobenes ldap3. `leer=True` + `result=…` stellt die Antwort eines Verzeichnisses
    nach, das die Suche mit einem VERWEIS statt mit Einträgen beantwortet."""
    mod = types.ModuleType("ldap3")
    mod.NONE, mod.BASE = "NONE", "BASE"
    # Die Attrappe bildet nach, was der Code von ldap3 benutzt — seit F-12 auch `Tls` und die
    # AUTO_BIND-Konstanten. Fehlten sie, prüfte die Suite eine Fassung des Moduls, die es nicht
    # gibt, und der Härtungsschritt liefe hier ins Leere.
    mod.AUTO_BIND_NO_TLS = "NO_TLS"
    mod.AUTO_BIND_TLS_BEFORE_BIND = "TLS_BEFORE_BIND"

    class Tls:
        def __init__(self, **kw):
            self.kw = kw
            mitschrift.append(("Tls", kw))

    mod.Tls = Tls

    class Eintrag:
        entry_dn = "uid=alice,ou=people,dc=example,dc=com"

        def __contains__(self, name):
            return False

    class Server:
        def __init__(self, host, **kw):
            mitschrift.append(("Server", kw))

    class Connection:
        def __init__(self, server, **kw):
            mitschrift.append(("Connection", kw))
            self.entries = [] if leer else [Eintrag()]
            if result is not None:
                self.result = result

        def start_tls(self):
            pass

        def bind(self):
            return True

        def search(self, *a, **kw):
            return True

        def unbind(self):
            pass

    mod.Server, mod.Connection = Server, Connection
    utils = types.ModuleType("ldap3.utils")
    conv = types.ModuleType("ldap3.utils.conv")
    conv.escape_filter_chars = lambda v, encoding=None: v
    dn = types.ModuleType("ldap3.utils.dn")
    dn.escape_rdn = lambda v: v
    return {"ldap3": mod, "ldap3.utils": utils, "ldap3.utils.conv": conv, "ldap3.utils.dn": dn}


mitschrift = []
vorher = {name: sys.modules.get(name) for name in
          ("ldap3", "ldap3.utils", "ldap3.utils.conv", "ldap3.utils.dn")}
try:
    sys.modules.update(stub_ldap3(mitschrift))
    LDAPClient(cfg_svc if HAT_LDAP3 else TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
        ldap_bind_dn=SVC_DN, ldap_bind_password=SVC_PW,
        ldap_user_base="ou=people,dc=example,dc=com")).authenticate("alice", "egal")
    LDAPClient(TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
        ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com",
    )).authenticate("alice", "egal")
finally:
    for name, mod in vorher.items():
        if mod is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = mod

verbindungen = [kw for art, kw in mitschrift if art == "Connection"]
server = [kw for art, kw in mitschrift if art == "Server"]
assert len(verbindungen) == 3, f"erwartet: Such-Bind + zwei Benutzer-Binds, war {len(verbindungen)}"
assert all(kw.get("auto_referrals") is False for kw in verbindungen), verbindungen
assert server and all(kw.get("allowed_referral_hosts") == [] for kw in server), server
ok("jede Verbindung setzt auto_referrals=False, jeder Server allowed_referral_hosts=[]")

# ---------- A-regression-9: der verworfene Verweis darf nicht STUMM sein ----------
# Der F-28-Fix hat einen Preis: Mit `auto_referrals=False` endet eine Suche, die das Verzeichnis
# per Verweis beantwortet, ergebnislos — `authenticate()` gibt None zurück, und die App zeigt
# „Passwort falsch". Wer über mehrere AD-Domänen sucht, sah das nach dem Update für JEDEN Nutzer
# und hatte nichts, was auf die Ursache zeigt: Der Global-Catalog-Hinweis stand nur im Quelltext
# und im CHANGELOG. Jetzt schreibt der Fall eine Zeile ins Sicherheits-Log.
import io as _io, logging as _logging          # noqa: E402
from tinysesam.security import seclog as _seclog  # noqa: E402

# Die Verweis-Adresse kommt aus FREMDER Hand: ein Umbruch darin wäre eine zusätzliche,
# frei erfundene Zeile in genau dem Log, das fail2ban liest (Log-Injection).
_VERWEIS = ("ldap://fremd.example.com/dc=example,dc=com\n"
            "2026-09-22 00:00:00 WARNING failed login user=opfer ip=203.0.113.9 method=password")


def _mit_seclog(fn):
    puffer = _io.StringIO()
    haken = _logging.StreamHandler(puffer)
    _seclog.addHandler(haken)
    try:
        fn()
    finally:
        _seclog.removeHandler(haken)
    return puffer.getvalue()


_cfg_verweis = TinySesamConfig(
    db_path=":memory:", password_enabled=True, ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
    ldap_bind_dn=SVC_DN, ldap_bind_password=SVC_PW,
    ldap_user_base="ou=people,dc=example,dc=com", ldap_user_filter="(uid={username})")
_vorher = {name: sys.modules.get(name) for name in
           ("ldap3", "ldap3.utils", "ldap3.utils.conv", "ldap3.utils.dn")}
try:
    sys.modules.update(stub_ldap3([], leer=True,
                                  result={"result": 10, "referrals": [_VERWEIS]}))
    _text = _mit_seclog(lambda: LDAPClient(_cfg_verweis).authenticate("alice", "egal"))
    # Gegenprobe: dieselbe leere Suche OHNE Verweis ist ein gewöhnliches „Konto gibt es nicht"
    # und darf das Log nicht fluten.
    sys.modules.update(stub_ldap3([], leer=True, result={"result": 0, "referrals": []}))
    _still = _mit_seclog(lambda: LDAPClient(_cfg_verweis).authenticate("alice", "egal"))
finally:
    for name, mod in _vorher.items():
        if mod is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = mod

assert "VERWEIS" in _text and "referral" in _text, f"kein Hinweis auf den Verweis: {_text[:200]!r}"
# Auf den Host wird mit Wortgrenzen geprüft, nicht per Teilzeichenkette: `x-fremd.example.com.evil`
# enthielte den Namen ebenfalls, wäre aber ein anderer Host (CodeQL py/incomplete-url-substring-
# sanitization — hier eine Testzusage, aber dieselbe Falle).
import re as _re_verweis  # noqa: E402
assert _re_verweis.search(r"(?<![\w.-])fremd\.example\.com(?![\w.-])", _text), \
    f"der verwiesene Host fehlt: {_text[:200]!r}"
assert "Global Catalog" in _text and "3268" in _text, f"kein Betriebs-Hinweis: {_text[:200]!r}"
assert "user=alice" in _text, _text[:200]
assert len(_text.strip().splitlines()) == 1, f"der Verweis hat eine Zeile eingeschoben: {_text!r}"
assert "ip=203.0.113.9" not in _text, f"Log-Injection über die Verweis-Adresse: {_text!r}"
assert _still.strip() == "", f"eine gewöhnliche leere Suche meldet sich: {_still[:120]!r}"
ok("verworfener Verweis: eine Logzeile mit Host und Global-Catalog-Hinweis (Umbruch entschärft)")

# Nebenbefund zu F-28: Ein Dienstkonto-DN ohne Passwort lehnt ldap3 ab; der Fehler wird im
# Login verschluckt und sieht für jeden Nutzer wie ein falsches Passwort aus. Deshalb fällt die
# Kombination jetzt schon beim Aufbau der Konfiguration auf, nicht erst im Betrieb.
from tinysesam.konfigpruefung import pruefe

_gemeinsam = dict(db_path=":memory:", ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
                  ldap_user_base="ou=people,dc=example,dc=com")
_fehler, _warn = pruefe(TinySesamConfig(ldap_bind_dn=SVC_DN, **_gemeinsam))
assert any("ldap_bind_password" in w for w in _warn), _warn
assert not _fehler, _fehler
_, _warn_ok = pruefe(TinySesamConfig(ldap_bind_dn=SVC_DN, ldap_bind_password=SVC_PW, **_gemeinsam))
assert not any("ldap_bind_password" in w for w in _warn_ok), _warn_ok
_, _warn_anon = pruefe(TinySesamConfig(**_gemeinsam))          # anonyme Suche bleibt still
assert not any("ldap_bind_password" in w for w in _warn_anon), _warn_anon
ok("ldap_bind_dn ohne ldap_bind_password wird beim Aufbau gemeldet, nicht erst beim Login")

# ---------- F-12: der Transport ----------
# Drei Mängel auf einmal: Vorgabe war Klartext, das Zertifikat wurde nie geprüft, und das
# Dienstkonto band sich AN, bevor StartTLS die Leitung verschlüsselte — sein Passwort war also
# schon über das Netz. Ein Mitleser brauchte keinen Angriff, nur Geduld.
_mit12 = []
_vorher12 = {n: sys.modules.get(n) for n in ("ldap3", "ldap3.utils", "ldap3.utils.conv", "ldap3.utils.dn")}
sys.modules.update(stub_ldap3(_mit12))
try:
    # (a) TLS-Objekt mit Zertifikatsprüfung geht an den Server — vorher gab es gar keines.
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldaps://dir.example.com",
                               ldap_user_dn_template="uid={username},dc=x")).authenticate("alice", "pw")
    _tls_kw = [kw for art, kw in _mit12 if art == "Tls"]
    assert _tls_kw, f"kein Tls-Objekt gebaut: {_mit12[:3]}"
    import ssl as _ssl
    assert _tls_kw[0]["validate"] == _ssl.CERT_REQUIRED, _tls_kw[0]
    _srv_kw = [kw for art, kw in _mit12 if art == "Server"]
    assert _srv_kw and _srv_kw[0].get("tls") is not None, _srv_kw
    ok("F-12: der Server bekommt ein TLS-Objekt mit Zertifikatsprüfung")

    # (b) Eigene CA-Datei wandert durch.
    _mit12.clear()
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldaps://dir.example.com", ldap_tls_ca_file="/etc/ssl/eigene.pem",
                               ldap_user_dn_template="uid={username},dc=x")).authenticate("alice", "pw")
    assert [kw for art, kw in _mit12 if art == "Tls"][0]["ca_certs_file"] == "/etc/ssl/eigene.pem"
    ok("F-12: eine eigene CA-Datei wird durchgereicht")

    # (c) Abschaltbar — aber dann ausdrücklich ohne Prüfung, nicht heimlich.
    _mit12.clear()
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldaps://dir.example.com", ldap_tls_verify=False,
                               ldap_user_dn_template="uid={username},dc=x")).authenticate("alice", "pw")
    assert [kw for art, kw in _mit12 if art == "Tls"][0]["validate"] == _ssl.CERT_NONE
    ok("F-12: ldap_tls_verify=False schaltet die Prüfung ab (und wird beim Aufbau gemeldet)")

    # (d) Der Kern: Das Dienstkonto bindet erst NACH dem TLS-Upgrade.
    _mit12.clear()
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldap://dir.example.com", ldap_start_tls=True,
                               ldap_bind_dn="cn=svc,dc=x", ldap_bind_password="geheim",
                               ldap_user_base="dc=x")).authenticate("alice", "pw")
    _conns = [kw for art, kw in _mit12 if art == "Connection"]
    assert _conns, _mit12
    assert _conns[0].get("auto_bind") == "TLS_BEFORE_BIND", \
        f"das Dienstkonto bindet vor dem TLS-Upgrade: auto_bind={_conns[0].get('auto_bind')!r}"
    ok("F-12: das Dienstkonto bindet erst nach dem TLS-Upgrade, nicht davor")

    # Gegenprobe: ohne StartTLS gibt es nichts hochzuschalten — dann kein TLS_BEFORE_BIND.
    _mit12.clear()
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldaps://dir.example.com",
                               ldap_bind_dn="cn=svc,dc=x", ldap_bind_password="geheim",
                               ldap_user_base="dc=x")).authenticate("alice", "pw")
    assert [kw for art, kw in _mit12 if art == "Connection"][0].get("auto_bind") == "NO_TLS"
    ok("F-12: bei ldaps:// ist die Leitung schon verschlüsselt — kein zusätzliches Upgrade")
finally:
    for n, m in _vorher12.items():
        if m is None:
            sys.modules.pop(n, None)
        else:
            sys.modules[n] = m

# Und die Konfigurationsprüfung fängt den Klartext-Betrieb beim Aufbau ab.
def _ldap_befunde(**kw):
    f, w = pruefe(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  passkey_enabled=False, ldap_enabled=True,
                                  ldap_user_dn_template="uid={username},dc=x", **kw))
    return ([x for x in f if "ldap" in x.lower()], [x for x in w if "ldap" in x.lower()])


assert len(_ldap_befunde(ldap_url="ldap://dir.example.com")[0]) == 1
assert len(_ldap_befunde(ldap_url="ldap://dir.example.com", ldap_allow_plaintext=True)[1]) == 1
assert _ldap_befunde(ldap_url="ldap://dir.example.com", ldap_allow_plaintext=True, ldap_start_tls=True) == ([], [])
assert _ldap_befunde(ldap_url="ldaps://dir.example.com") == ([], [])
assert len(_ldap_befunde(ldap_url="ldaps://dir.example.com", ldap_tls_verify=False)[1]) == 1
assert len(_ldap_befunde(ldap_url="ldaps://dir.example.com", ldap_tls_ca_file="/gibt/es/nicht.pem")[0]) == 1
ok("F-12: Klartext ohne ausdrückliche Erlaubnis ist ein Aufbaufehler, kein Betriebsproblem")

# ---------- F-11: die Zuordnung hängt an einer stabilen Kennung, nicht am Namen ----------
# Ein Benutzername ist nicht fälschungssicher. Wer im Verzeichnis umbenennt oder ein gelöschtes
# Konto unter demselben Namen neu anlegt, bekam bis 0.19.0 dasselbe lokale Konto mitsamt seinen
# Rollen — ohne das lokale Passwort zu kennen.
db11, auth11, c11 = build(ldap_auto_create=True)

# (1) Neues Konto: wird angelegt UND gebunden.
auth11.ldap = FakeLDAP({"alice": {"password": "pw", "id": "uuid-alice", "email": "a@corp"}})
assert auth11.check_ldap("alice", "pw") is not None
_uid_a = auth11.store.get_user_by_name("alice")["id"]
assert auth11.store.get_federated_kennung("ldap", _uid_a) == "uuid-alice"
ok("F-11: ein neu angelegtes Konto wird an die Kennung des Verzeichnisses gebunden")

# (2) Umbenennung im Verzeichnis: dieselbe Kennung, neuer Name → dasselbe Konto.
auth11.ldap = FakeLDAP({"alice.neu": {"password": "pw", "id": "uuid-alice"}})
_u = auth11.check_ldap("alice.neu", "pw")
assert _u is not None and _u["id"] == _uid_a, f"Umbenennung ergab ein anderes Konto: {_u}"
assert auth11.store.get_user_by_name("alice.neu") is None, "es wurde ein zweites Konto angelegt"
ok("F-11: eine Umbenennung im Verzeichnis ist kein Kontowechsel")

# (3) DER ANGRIFF: neue Kennung unter dem alten Namen → abgewiesen.
auth11.ldap = FakeLDAP({"alice": {"password": "pw", "id": "uuid-FREMD"}})
assert auth11.check_ldap("alice", "pw") is None, \
    "ein neues Verzeichniskonto unter demselben Namen hat das lokale Konto übernommen"
assert any(e["event"] == "ldap_kennung_wechsel" for e in auth11.store.recent_audit(limit=10))
ok("F-11: ein neues Verzeichniskonto unter altem Namen erbt das lokale Konto NICHT")

# (4) Bestandsfall: ein Konto ohne Bindung wird beim nächsten Login nachgebunden (PO-Entscheid).
_uid_b = auth11.create_user("bestand")
assert auth11.store.get_federated_kennung("ldap", _uid_b) is None
auth11.ldap = FakeLDAP({"bestand": {"password": "pw", "id": "uuid-bestand"}})
assert auth11.check_ldap("bestand", "pw") is not None
assert auth11.store.get_federated_kennung("ldap", _uid_b) == "uuid-bestand"
assert any(e["event"] == "ldap_kennung_gebunden" for e in auth11.store.recent_audit(limit=10))
ok("F-11: ein Bestandskonto wird beim nächsten Login nachgebunden — einmal, mit Audit-Zeile")

# …und danach greift der Riegel aus (3) auch für dieses Konto.
auth11.ldap = FakeLDAP({"bestand": {"password": "pw", "id": "uuid-anders"}})
assert auth11.check_ldap("bestand", "pw") is None
ok("F-11: …danach ist auch dieses Konto gegen den Namenswechsel geschützt")

# Der Betreiber kann die Bindung lösen, wenn im Verzeichnis wirklich umgezogen wurde.
assert auth11.loese_fremde_bindung("ldap", _uid_b) == 1
assert auth11.check_ldap("bestand", "pw") is not None
assert auth11.store.get_federated_kennung("ldap", _uid_b) == "uuid-anders"
ok("F-11: der Betreiber löst die Bindung — ein bewusster Schritt, kein Nebeneffekt")

# Ohne Kennung bleibt es beim Namen (Bestandsverzeichnisse), aber es wird gesagt.
db11b, auth11b, c11b = build(ldap_auto_create=True)
auth11b.ldap = FakeLDAP({"ohne": {"password": "pw"}})     # kein "id"
import io as _io11, logging as _log11                                      # noqa: E402
from tinysesam import security as _sec11                                   # noqa: E402
_sec11.einmal_melden_zuruecksetzen()
_puffer11 = _io11.StringIO()
_haken11 = _log11.StreamHandler(_puffer11)
_sec11.seclog.addHandler(_haken11)
try:
    assert auth11b.check_ldap("ohne", "pw") is not None
finally:
    _sec11.seclog.removeHandler(_haken11)
assert "keine stabile Kennung" in _puffer11.getvalue(), _puffer11.getvalue()[:200]
ok("F-11: ein Verzeichnis ohne stabile Kennung meldet sich, sperrt aber niemanden aus")

# …es sei denn, der Betreiber verlangt sie.
db11c, auth11c, c11c = build(ldap_auto_create=True, federation_require_stable_id=True)
auth11c.ldap = FakeLDAP({"ohne": {"password": "pw"}})
assert auth11c.check_ldap("ohne", "pw") is None
ok("F-11: federation_require_stable_id=True weist eine Anmeldung ohne Kennung ab")

# A-4 (Angriff auf H-4): Ohne stabile Kennung wurde nie gebunden — das LDAP-Konto galt als lokal
# und bekam einen Reset-Link. Das neue lokale Passwort stach danach das Verzeichnis, auch wenn das
# Konto dort gesperrt war. Hier über den ECHTEN Login-Weg, nicht über eine Bindung von Hand.
db11d, auth11d, c11d = build(ldap_auto_create=True, password_reset_enabled=True,
                             base_url="https://auth.example.com")
_post11d = []
auth11d.set_mailer(lambda to, s, t, html=None: _post11d.append(to))
auth11d.ldap = FakeLDAP({"bob": {"password": "ldappw", "email": "bob@example.com"}})   # kein "id"
assert c11d.post("/auth/login", data={"username": "bob", "password": "ldappw"},
                 follow_redirects=False).status_code == 303
_uid_bob = auth11d.store.get_user_by_name("bob")["id"]
assert auth11d.nur_foederiert(_uid_bob), "LDAP-Konto ohne Kennung gilt als lokal"
c11d.get("/auth/logout")
assert c11d.post("/auth/forgot", data={"email": "bob@example.com"}).status_code == 200
assert _post11d == [], f"LDAP-Konto ohne Kennung bekam einen Reset-Link: {_post11d}"
ok("A-4: ein LDAP-Konto ohne stabile Kennung bekommt über den echten Login-Weg keinen Reset-Link")
# Kommt später eine echte Kennung, ersetzt sie den Platzhalter (Nachbindung, kein Kennungswechsel).
auth11d.ldap = FakeLDAP({"bob": {"password": "ldappw", "id": "uuid-bob"}})
assert auth11d.check_ldap("bob", "ldappw") is not None, "der Platzhalter blockiert die echte Kennung"
assert auth11d.store.get_federated_kennung("ldap", _uid_bob) == "uuid-bob"
# Eine Kennung in Platzhalter-Form aus dem Verzeichnis wird abgewiesen — sie träfe sonst das
# Konto, dessen ID sie nennt.
_adm11d = auth11d.store.get_user_by_name("admin")["id"]
auth11d.store.link_federated("ldap", f"{auth11d._OHNE_KENNUNG}{_adm11d}", _adm11d, 0)
auth11d.ldap = FakeLDAP({"mallory": {"password": "m", "id": f"{auth11d._OHNE_KENNUNG}{_adm11d}"}})
assert auth11d.check_ldap("mallory", "m") is None, "Platzhalter-Kennung übernahm ein fremdes Konto"
ok("A-4: echte Kennung ersetzt den Platzhalter; Platzhalter-Form aus dem Verzeichnis abgewiesen")

for _d in (db11, db11b, db11c, db11d):
    os.remove(_d)

# ---------- F-19: Gruppen aus dem Verzeichnis werden nicht mehr als Teilstring verglichen ----------
# Bis 0.20.0 verglich LDAP IMMER per Teilstring, `group_match` war wirkungslos: `admin` passte auf
# `cn=nicht-admin,…`, `staff` auf `cn=staffextern,…`. Wer im Verzeichnis eine Gruppe benennen
# darf (in vielen AD-Umgebungen jeder Abteilungsleiter), bekam damit Rolle und Admin-Flag.
db19, auth19, c19 = build(ldap_allowed_groups=["staff"],
                          ldap_group_role_map={"admin": "__admin__", "cn=redaktion": "redaktion"})
auth19.ldap = FakeLDAP({
    "eve": {"password": "x", "id": "e1",
            "groups": ["cn=staffextern,ou=groups,dc=corp", "cn=nicht-admin,ou=groups,dc=corp"]},
    "bob": {"password": "x", "id": "b1",
            "groups": ["CN=Staff,OU=Groups,DC=corp", "cn=admin,ou=groups,dc=corp",
                       "cn=redaktion,ou=groups,dc=corp"]},
    "mia": {"password": "x", "id": "m1",
            "groups": ["cn=staff,ou=groups,dc=corp", "cn=nicht-admin,ou=groups,dc=corp",
                       "cn=redaktion-alt,ou=groups,dc=corp"]},
})
assert auth19.check_ldap("eve", "x") is None, "staff passt nicht auf cn=staffextern"
assert any(z["event"] == "ldap_group_denied" and z["username"] == "eve"
           for z in auth19.store.recent_audit(20)), "die Abweisung am Gruppen-Gate ist stumm"
ok("F-19: ldap_allowed_groups=['staff'] lässt cn=staffextern nicht durch (und sagt es im Audit-Log)")
_mia = auth19.check_ldap("mia", "x")
assert _mia is not None and not _mia["is_admin"], "admin passt auf cn=nicht-admin"
assert auth19.store.get_roles(_mia["id"]) == [], auth19.store.get_roles(_mia["id"])
ok("F-19: 'admin' und 'cn=redaktion' treffen weder cn=nicht-admin noch cn=redaktion-alt")
_bob = auth19.check_ldap("bob", "x")
assert _bob is not None and _bob["is_admin"], "der exakte CN-Treffer muss weiter greifen"
assert auth19.store.get_roles(_bob["id"]) == ["redaktion"], auth19.store.get_roles(_bob["id"])
ok("F-19: der gewohnte Schlüssel ('staff', 'cn=redaktion') greift weiter — Gross/klein egal")
os.remove(db19)

# Die ausdrückliche Rückkehr zum alten Vergleich bleibt möglich — jetzt wirkt der Schalter.
db19b, auth19b, _ = build(ldap_allowed_groups=["staff"], group_match="substring")
auth19b.ldap = FakeLDAP({"eve": {"password": "x", "id": "e1",
                                 "groups": ["cn=staffextern,ou=groups,dc=corp"]}})
assert auth19b.check_ldap("eve", "x") is not None
ok("F-19: group_match='substring' holt den Teilstring-Vergleich ausdrücklich zurück")
os.remove(db19b)

from tinysesam.manager import gruppe_passt  # noqa: E402
assert gruppe_passt("cn=a\\,b", "cn=a\\,b,ou=g,dc=x", dn=True), "maskiertes Komma zerlegt den DN nicht"
assert not gruppe_passt("a", "cn=a\\,b,ou=g,dc=x", dn=True)
assert gruppe_passt("cn=staff,ou=groups,dc=corp", "CN=Staff, OU=Groups, DC=corp", dn=True)
assert not gruppe_passt("staff", "cn=staff,ou=g", dn=False), "ohne dn=True bleibt es beim exakten Text"
assert not gruppe_passt("", "cn=x", dn=True)
ok("F-19: gruppe_passt zerlegt DNs an unmaskierten Kommas, vergleicht ganzen DN/ersten RDN/Wert")

# A-3 (Angriff auf F-19): Das README-Beispiel `{"cn=admins,ou=g": "__admin__"}` ist ein Teil-DN.
# Nach dem ersten Fix traf es `cn=admins,ou=g,dc=example,dc=com` nicht mehr — Admin-Mapping still
# weg, als ldap_allowed_groups jeder Nutzer abgewiesen.
assert gruppe_passt("cn=admins,ou=g", "cn=admins,ou=g,dc=example,dc=com", dn=True)
assert gruppe_passt("CN=Admins, OU=G", "cn=admins,ou=g,dc=example,dc=com", dn=True)
assert not gruppe_passt("ou=g", "cn=admins,ou=g,dc=example,dc=com", dn=True), "nur von vorn"
assert not gruppe_passt("cn=admin,ou=g", "cn=admins,ou=g,dc=example,dc=com", dn=True)
assert not gruppe_passt("cn=admins,ou=g,dc=example,dc=com,dc=x", "cn=admins,ou=g,dc=example,dc=com", dn=True)
db19c, auth19c, _ = build(ldap_allowed_groups=["cn=admins,ou=g"],
                          ldap_group_role_map={"cn=admins,ou=g": "__admin__", "ou=g": "alle"})
auth19c.ldap = FakeLDAP({"ada": {"password": "x", "id": "a1",
                                 "groups": ["cn=admins,ou=g,dc=example,dc=com"]}})
from tinysesam import security as _sec19                    # noqa: E402
_sec19.einmal_melden_zuruecksetzen()
_puffer19 = __import__("io").StringIO()
_haken19 = __import__("logging").StreamHandler(_puffer19)
_sec19.seclog.addHandler(_haken19)
try:
    _ada = auth19c.check_ldap("ada", "x")
finally:
    _sec19.seclog.removeHandler(_haken19)
assert _ada is not None, "README-Schlüssel als ldap_allowed_groups weist jeden ab"
assert _ada["is_admin"], "README-Schlüssel als Admin-Mapping greift nicht"
assert auth19c.store.get_roles(_ada["id"]) == [], "Teilstring 'ou=g' darf nicht treffen"
# Der Schlüssel, der nur noch als Teilstring träfe, fällt nicht still weg: eine Zeile im Log.
assert "'ou=g'" in _puffer19.getvalue() and "Teilstring" in _puffer19.getvalue(), _puffer19.getvalue()[:300]
assert "cn=admins,ou=g'" not in _puffer19.getvalue(), "ein greifender Schlüssel darf nicht warnen"
ok("A-3: Teil-DN von vorn (README-Beispiel) greift wieder; ein reiner Teilstring-Schlüssel meldet sich")
os.remove(db19c)

# ---------- F-23: ein Ausfall des Verzeichnisses ist kein Fehlversuch ----------
# Bis 0.20.0 endete jeder Fehler in `authenticate()` als None, also als „Passwort falsch": ein
# Fehlversuch gegen Konto und IP, `failed login` für fail2ban. Nach ein paar Minuten Ausfall
# waren genau die Nutzer gesperrt, die nichts falsch gemacht hatten.
from tinysesam.ldap_ import VerzeichnisNichtErreichbar  # noqa: E402


class AusfallLDAP:
    def authenticate(self, username, password):
        raise VerzeichnisNichtErreichbar("LDAP-Verzeichnis ldap://dummy nicht benutzbar: Test")


db23, auth23, c23 = build()
auth23.ldap = AusfallLDAP()
import io as _io23, logging as _log23                     # noqa: E402
from tinysesam.security import seclog as _seclog23       # noqa: E402
_puffer23 = _io23.StringIO()
_haken23 = _log23.StreamHandler(_puffer23)
_seclog23.addHandler(_haken23)
try:
    antworten23 = [c23.post("/auth/login", data={"username": "alice", "password": "egal"})
                   for _ in range(auth23.sec("max_login_attempts") + 2)]
finally:
    _seclog23.removeHandler(_haken23)
assert all(a.status_code == 503 for a in antworten23), [a.status_code for a in antworten23]
assert "nicht erreichbar" in antworten23[0].text, antworten23[0].text[:300]
assert auth23.store.count_fails(0, username="alice") == 0, "der Ausfall wurde als Fehlversuch verbucht"
assert not auth23.is_locked("alice", "testclient"), "ein Ausfall sperrt das Konto"
assert "failed login" not in _puffer23.getvalue(), "fail2ban bekäme einen Ausfall als Angriff"
assert "LDAP nicht erreichbar" in _puffer23.getvalue(), _puffer23.getvalue()[:300]
assert any(z["event"] == "ldap_unavailable" for z in auth23.store.recent_audit(20))
ok("F-23: Verzeichnis-Ausfall → 503, kein Fehlversuch, keine Sperre, kein 'failed login', eigene Audit-Zeile")
# Gegenprobe: dieselbe Route mit einem erreichbaren Verzeichnis und falschem Passwort zählt.
auth23.ldap = FakeLDAP({"alice": {"password": "richtig"}})
assert c23.post("/auth/login", data={"username": "alice", "password": "falsch"}).status_code == 401
assert auth23.store.count_fails(0, username="alice") == 1
ok("F-23: …ein echtes falsches Passwort bleibt ein Fehlversuch")
os.remove(db23)

# A-1 (Angriff auf F-23): Während des Ausfalls blieb auch das falsche LOKALE Passwort
# unverbucht — gegen den lokalen Admin, das Notfallkonto, war beliebig oft zu raten (verteilt
# über IPs griff nur das IP-Ratelimit), und das richtige Passwort kam danach trotz
# max_login_attempts durch.
db23a, auth23a, c23a = build()
auth23a.ldap = AusfallLDAP()
_max23a = auth23a.sec("max_login_attempts")
_puffer23a = _io23.StringIO()
_haken23a = _log23.StreamHandler(_puffer23a)
_seclog23.addHandler(_haken23a)
try:
    _antw23a = [c23a.post("/auth/login", data={"username": "admin", "password": f"falsch{i}"}).status_code
                for i in range(_max23a)]
finally:
    _seclog23.removeHandler(_haken23a)
assert all(s == 503 for s in _antw23a), _antw23a
assert auth23a.store.count_fails(0, username="admin") == _max23a, \
    "falsches lokales Passwort während des Ausfalls wurde nicht verbucht"
assert auth23a.is_locked("admin", "testclient"), "lokaler Admin während des Ausfalls unbegrenzt ratbar"
assert "failed login" in _puffer23a.getvalue(), "fail2ban sieht das Raten am lokalen Konto nicht"
_r23a = c23a.post("/auth/login", data={"username": "admin", "password": "lokalpw"}, follow_redirects=False)
assert _r23a.status_code == 429, f"richtiges Passwort kam nach {_max23a} Fehlversuchen durch: {_r23a.status_code}"
# Der Verzeichnis-Anteil bleibt entschuldigt: das LDAP-Konto ohne lokales Passwort zählt nicht.
c23a.post("/auth/login", data={"username": "alice", "password": "x"})
assert auth23a.store.count_fails(0, username="alice") == 0
ok("A-1: Ausfall entschuldigt nur das Verzeichnis — ein falsches LOKALES Passwort zählt und sperrt")
os.remove(db23a)

if HAT_LDAP3:
    # Gegen das ECHTE ldap3: ein Port, auf dem niemand lauscht. Die Ausnahme muss aus der
    # Bibliothek kommen, nicht aus unserer Attrappe — sonst wäre die Zuordnung der Fehlerarten
    # (`_ausfall_arten`) ungemessen.
    _s = socket.socket()
    _s.bind(("127.0.0.1", 0))
    _toter_port = _s.getsockname()[1]
    _s.close()
    for _cfg in (TinySesamConfig(db_path=":memory:", password_enabled=True, ldap_enabled=True,
                                 ldap_url=f"ldap://127.0.0.1:{_toter_port}", ldap_allow_plaintext=True,
                                 ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com"),
                 TinySesamConfig(db_path=":memory:", password_enabled=True, ldap_enabled=True,
                                 ldap_url=f"ldap://127.0.0.1:{_toter_port}", ldap_allow_plaintext=True,
                                 ldap_bind_dn=SVC_DN, ldap_bind_password=SVC_PW,
                                 ldap_user_base="ou=people,dc=example,dc=com")):
        try:
            LDAPClient(_cfg).authenticate("alice", "egal")
            _geworfen = False
        except VerzeichnisNichtErreichbar:
            _geworfen = True
        assert _geworfen, "ein toter Port endet wieder als 'Passwort falsch'"
    ok("F-23: echtes ldap3 gegen einen toten Port → VerzeichnisNichtErreichbar (Direkt- und Such-Bind)")
    # Und ein abgewiesenes Passwort gegen einen ECHTEN Server bleibt None, nicht Ausfall.
    _sa, _pa = lauscher()

    def _lehnt_ab(sock):
        try:
            conn, _ = sock.accept()
            conn.settimeout(5)
            daten = conn.recv(8192)
            mid, _op = zerlegen(daten)
            # BindResponse resultCode 49 = invalidCredentials
            conn.sendall(antwort(mid, 0x61, tlv(0x0A, b"\x31") + tlv(0x04, b"") + tlv(0x04, b"")))
            conn.recv(8192)
            conn.close()
        except Exception:
            pass   # der Client hat aufgelegt — für diesen Attrappen-Server kein Fehler

    threading.Thread(target=_lehnt_ab, args=(_sa,), daemon=True).start()
    assert LDAPClient(TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True,
        ldap_url=f"ldap://127.0.0.1:{_pa}", ldap_allow_plaintext=True,
        ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com")).authenticate(
        "alice", "falsch") is None
    _sa.close()
    ok("F-23: invalidCredentials vom echten Server bleibt None (Fehlversuch), kein Ausfall")

# ---------- F-29: LDAP- und lokale Anmeldung sind im Audit-Log unterscheidbar ----------
db29, auth29, c29 = build()
auth29.ldap = FakeLDAP({"ldapnutzer": {"password": "lp", "id": "l1"}})
c29.post("/auth/login", data={"username": "ldapnutzer", "password": "lp"}, follow_redirects=False)
c29.get("/auth/logout")
c29.post("/auth/login", data={"username": "admin", "password": "lokalpw"}, follow_redirects=False)
c29.get("/auth/logout")
c29.post("/auth/login", data={"username": "niemand", "password": "x"})
_zeilen29 = auth29.store.recent_audit(50)
_ereignisse = {(z["event"], z["username"]) for z in _zeilen29}
assert ("login_ldap", "ldapnutzer") in _ereignisse, _ereignisse
assert ("login_lokal", "admin") in _ereignisse, _ereignisse
assert ("login_ldap", "admin") not in _ereignisse and ("login_lokal", "ldapnutzer") not in _ereignisse
_fail29 = [z for z in _zeilen29 if z["event"] == "login_fail" and z["username"] == "niemand"]
assert _fail29 and "quelle=lokal+ldap" in (_fail29[0]["detail"] or ""), _fail29
ok("F-29: login_ldap / login_lokal getrennt, ein Fehlversuch nennt quelle=lokal+ldap")
os.remove(db29)
# Ohne LDAP bleibt das Audit-Log wie bisher — keine neue Zeile für jeden lokalen Login.
db29b = os.path.join(tempfile.mkdtemp(), "t.db")
auth29b = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db29b, rp_name="Test",
                                    passkey_enabled=False, cookie_secure=False))
auth29b.ensure_admin("admin", "lokalpw")
_app29b = FastAPI()
_app29b.include_router(auth29b.router())
TestClient(_app29b).post("/auth/login", data={"username": "admin", "password": "lokalpw"},
                         follow_redirects=False)
assert not any(z["event"].startswith("login_l") for z in auth29b.store.recent_audit(20))
ok("F-29: ohne ldap_enabled keine Zusatzzeile")
os.remove(db29b)

# ---------- F-30: die Konfigurationsprüfung nennt keine Abhilfe, die sie selbst ablehnt ----------
from tinysesam import konfigpruefung as _kp  # noqa: E402
_f30, _w30 = _kp.pruefe(TinySesamConfig(db_path=":memory:", password_enabled=False,
                                        passkey_enabled=False, ldap_enabled=True,
                                        ldap_url="ldaps://ldap.example.com"))
_meldung30 = next(f for f in _f30 if "Keine einzige Anmelde-Methode" in f)
assert "ldap_enabled=True," not in _meldung30.split("LDAP allein")[0], _meldung30
assert "password_enabled=True" in _meldung30.split("LDAP allein")[1], _meldung30
assert any("ldap_enabled=True, aber password_enabled=False" in w for w in _w30), _w30
# Gegenprobe: die genannte Abhilfe wird tatsächlich angenommen.
_f30b, _w30b = _kp.pruefe(TinySesamConfig(db_path=":memory:", password_enabled=True,
                                          passkey_enabled=False, ldap_enabled=True,
                                          ldap_url="ldaps://ldap.example.com"))
assert not any("Keine einzige" in f for f in _f30b) and not any("password_enabled=False" in w for w in _w30b)
ok("F-30: 'keine Methode' nennt ldap_enabled nicht mehr als Abhilfe; LDAP ohne Passwortfeld warnt")

print("\nLDAP-BACKEND OK ✅")
