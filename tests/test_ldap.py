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
                "name": u.get("name", username), "groups": u.get("groups", [])}


def build(**cfgkw):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
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
    assert LDAPClient(cfg_svc).authenticate("alice", "egal") is None
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
    info = LDAPClient(cfg_usr).authenticate("alice", "NUTZER-GEHEIM-456")
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
def stub_ldap3(mitschrift):
    mod = types.ModuleType("ldap3")
    mod.NONE, mod.BASE = "NONE", "BASE"

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
            self.entries = [Eintrag()]

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
        db_path=":memory:", password_enabled=True, ldap_enabled=True, ldap_url="ldap://dummy",
        ldap_bind_dn=SVC_DN, ldap_bind_password=SVC_PW,
        ldap_user_base="ou=people,dc=example,dc=com")).authenticate("alice", "egal")
    LDAPClient(TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True, ldap_url="ldap://dummy",
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

# Nebenbefund zu F-28: Ein Dienstkonto-DN ohne Passwort lehnt ldap3 ab; der Fehler wird im
# Login verschluckt und sieht für jeden Nutzer wie ein falsches Passwort aus. Deshalb fällt die
# Kombination jetzt schon beim Aufbau der Konfiguration auf, nicht erst im Betrieb.
from tinysesam.konfigpruefung import pruefe

_gemeinsam = dict(db_path=":memory:", ldap_enabled=True, ldap_url="ldap://dummy",
                  ldap_user_base="ou=people,dc=example,dc=com")
_fehler, _warn = pruefe(TinySesamConfig(ldap_bind_dn=SVC_DN, **_gemeinsam))
assert any("ldap_bind_password" in w for w in _warn), _warn
assert not _fehler, _fehler
_, _warn_ok = pruefe(TinySesamConfig(ldap_bind_dn=SVC_DN, ldap_bind_password=SVC_PW, **_gemeinsam))
assert not any("ldap_bind_password" in w for w in _warn_ok), _warn_ok
_, _warn_anon = pruefe(TinySesamConfig(**_gemeinsam))          # anonyme Suche bleibt still
assert not any("ldap_bind_password" in w for w in _warn_anon), _warn_anon
ok("ldap_bind_dn ohne ldap_bind_password wird beim Aufbau gemeldet, nicht erst beim Login")

print("\nLDAP-BACKEND OK ✅")
