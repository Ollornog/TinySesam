"""Batch B: LDAP/lldap backend — login against a directory, auto-create, group gate.
Uses a fake LDAP client (no server/ldap3 needed) and tests the integration."""
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
                "id": u.get("id")}   # stable identifier of the directory (F-11)


def build(**cfgkw):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    # `ldap_allow_plaintext=True`: This suite talks to a stub, there is neither a server
    # nor a network. Since F-12, `ldap://` without TLS would otherwise be a setup error — rightly so, but here
    # that would miss the point. The guard itself is measured separately below.
    cfgkw.setdefault("ldap_allow_plaintext", True)
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False, ldap_enabled=True, ldap_url="ldap://dummy", **cfgkw))
    auth.ensure_admin("admin", "lokalpw")   # local user with a local password
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, TestClient(app)


JSON = {"Accept": "application/json"}

# ---------- LDAP user without a local password → login + auto-create ----------
db, auth, c = build()
auth.ldap = FakeLDAP({"alice": {"password": "ldappw", "email": "alice@corp", "name": "Alice",
                                "groups": ["cn=staff,ou=groups,dc=corp"]}})
assert auth.store.get_user_by_name("alice") is None
r = c.post("/auth/login", data={"username": "alice", "password": "ldappw", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303, r.status_code
assert c.get("/geheim", headers=JSON).json() == {"u": "alice"}
u = auth.store.get_user_by_name("alice")
# Since the PO decision of 2026-09-25, LDAP is NOT trusted by default: The address only enters the account
# after a confirmation (federation_email_confirm, not at all here without mailer/base_url).
assert u and not u["email"] and u["display_name"] == "Alice", dict(u)
ok("LDAP login creates a local user automatically (name taken over, unconfirmed address not)")

# wrong LDAP password → 401
c.get("/auth/logout")
assert c.post("/auth/login", data={"username": "alice", "password": "falsch"}).status_code == 401
ok("wrong LDAP password → 401")
os.remove(db)

# ---------- local password keeps working alongside LDAP ----------
db, auth, c = build()
auth.ldap = FakeLDAP({})
r = c.post("/auth/login", data={"username": "admin", "password": "lokalpw", "next": "/"}, follow_redirects=False)
assert r.status_code == 303
ok("local password login still works (LDAP only a fallback)")
os.remove(db)

# ---------- Group gate ----------
db, auth, c = build(ldap_allowed_groups=["staff"])
auth.ldap = FakeLDAP({
    "bob": {"password": "x", "groups": ["cn=staff,ou=groups,dc=corp"]},      # allowed
    "eve": {"password": "x", "groups": ["cn=extern,ou=groups,dc=corp"]},     # not allowed
})
assert c.post("/auth/login", data={"username": "eve", "password": "x"}).status_code == 401
ok("Group gate: user without an allowed group → 401")
c.get("/auth/logout")
r = c.post("/auth/login", data={"username": "bob", "password": "x", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and c.get("/geheim", headers=JSON).json() == {"u": "bob"}
ok("Group gate: user with an allowed group → login")
os.remove(db)

# ---------- auto_create=False → no local user, no login ----------
db, auth, c = build(ldap_auto_create=False)
auth.ldap = FakeLDAP({"carol": {"password": "x"}})
assert c.post("/auth/login", data={"username": "carol", "password": "x"}).status_code == 401
ok("ldap_auto_create=False: unknown LDAP user is not created")
os.remove(db)

# ---------- F-14: an allowlist ADDRESS does not become first admin via LDAP ----------
# In many directories users maintain the `mail` attribute themselves, and LDAP has no proof like
# OIDC's `email_verified` claim. Whoever entered the admin address there was
# first admin of the instance at the first login: The guard from F-14 hung solely on the OIDC callback,
# the login route called `apply_factor` without proof, and "no proof" (None) meant
# "no IdP involved" there. Now the route explicitly passes "no proof" through (fail-closed).
def baue_ohne_admin(**cfgkw):
    """Like `build`, but WITHOUT `ensure_admin` — the bootstrap paths only apply while there is
    no admin. With the local admin from `build`, every check here would be green
    without measuring anything."""
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test",
                                     passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False, ldap_enabled=True,
                                     ldap_url="ldap://dummy", ldap_allow_plaintext=True, **cfgkw))
    app = FastAPI()
    app.include_router(auth.router())
    return db, auth, TestClient(app)


# Since the PO decision of 2026-09-24, the guard hangs on `ldap_email_trusted=False` — the operator
# thereby says that users maintain their `mail` attribute themselves. The default (trusted) is below.
db, auth, c = baue_ohne_admin(admin_identifiers=["boss@example.com"], ldap_email_trusted=False)
auth.ldap = FakeLDAP({"angreifer": {"password": "x", "email": "boss@example.com", "groups": []}})
r = c.post("/auth/login", data={"username": "angreifer", "password": "x"}, follow_redirects=False)
assert r.status_code == 303, r.status_code          # the sign-in itself remains allowed
u = auth.store.get_user_by_name("angreifer")
assert u is not None and not u["is_admin"], dict(u) if u else None
assert not auth.admin_exists(), "the instance now has an admin — via a mail attribute"
ok("F-14: an allowlist ADDRESS from an untrusted directory does not promote")
os.remove(db)

# The default `ldap_email_trusted=True` (PO decision B): The directory counts as maintained, its
# address as proven — and thereby carries rights, up to first admin. Since 2026-09-25 this is NOT
# the default any more (F-14 applies again); the operator states it explicitly for a maintained directory.
db, auth, c = baue_ohne_admin(admin_identifiers=["boss@example.com"], ldap_email_trusted=True)
auth.ldap = FakeLDAP({"boss": {"password": "x", "email": "boss@example.com", "groups": []}})
assert c.post("/auth/login", data={"username": "boss", "password": "x"},
              follow_redirects=False).status_code == 303
u = auth.store.get_user_by_name("boss")
assert u["email"] == "boss@example.com" and u["email_verified"] and u["is_admin"], dict(u)
ok("ldap_email_trusted=True: the directory address counts as proven and carries rights")
os.remove(db)

# Counter-check, otherwise the check above would also be green if the bootstrap were completely broken:
# An allowlist NAME still counts. It is only allowed without auto-create (otherwise the constructor
# guard forbids it) — the operator then created the account themselves.
db, auth, c = baue_ohne_admin(admin_identifiers=["chefin"], ldap_auto_create=False)
uid = auth.create_user("chefin", email="chefin@example.com")
auth.ldap = FakeLDAP({"chefin": {"password": "x", "email": "chefin@example.com", "groups": []}})
r = c.post("/auth/login", data={"username": "chefin", "password": "x"}, follow_redirects=False)
assert r.status_code == 303, r.status_code
assert auth.get_user(uid)["is_admin"], "the documented bootstrap path via the name is closed"
ok("... the allowlist NAME of a previously created account still promotes")
os.remove(db)

# ---------- B-umgehung-1: the guard also holds the SECOND login ----------
# The refusal above closes only THIS sign-in path. If LDAP created the account with the default
# `email_verified=1`, the account said "proven" although nothing was proven — and the next
# factor the attacker sets up himself in his freshly signed-in session (PIN,
# passkey: self-service) arrives without proof, reads the note and promotes after all. The
# bootstrap attack was thus still possible unchanged, just with one more click.
db, auth, c = baue_ohne_admin(admin_identifiers=["boss@example.com"], ldap_email_trusted=False,
                              pin_enabled=True, pin_login=True)
auth.ldap = FakeLDAP({"mallory": {"password": "x", "email": "boss@example.com", "groups": []}})
assert c.post("/auth/login", data={"username": "mallory", "password": "x"},
              follow_redirects=False).status_code == 303
mallory = auth.store.get_user_by_name("mallory")
assert not mallory["email_verified"], "LDAP creates with a proof that nobody provided"
assert c.post("/auth/pin/set", json={"pin": "246813"}).status_code == 200   # own session
c.get("/auth/logout")
c.cookies.clear()
r = c.post("/auth/pin", data={"username": "mallory", "pin": "246813"}, follow_redirects=False)
assert r.status_code == 303, r.status_code                   # the PIN login itself works
assert not auth.get_user(mallory["id"])["is_admin"], "first admin via the second jump"
assert not auth.admin_exists()
ok("B-umgehung-1: ... a self-configured second factor does not promote the address either")
os.remove(db)

# Counter-check: The same second jump with an account whose address someone vouched for (here
# the operator at creation) still promotes — otherwise a completely broken
# PIN promotion would be green above too.
db, auth, c = baue_ohne_admin(admin_identifiers=["boss@example.com"], ldap_auto_create=False,
                              pin_enabled=True, pin_login=True)
uid = auth.create_user("chefin", password="lokal12345", email="boss@example.com")
assert c.post("/auth/login", data={"username": "chefin", "password": "lokal12345"},
              follow_redirects=False).status_code == 303
assert auth.get_user(uid)["is_admin"], "the proven path is closed"
ok("... the proven address of a locally created account still promotes")
os.remove(db)

# ---------- B-umgehung-10: the lock of the LOGIN ROUTE measured individually ----------
# Two locks secure the same path: (1) the route explicitly passes "no proof" through,
# (2) an account created from the directory carries no proof at all. As long as both stand,
# removing (1) goes unnoticed anywhere — whoever rebuilds the pass-through later loses it
# unnoticed. Hence here an account that carries a REAL proof (the operator created
# it) and whose name the directory knows: Now everything hangs on (1).
db, auth, c = baue_ohne_admin(admin_identifiers=["boss@example.com"], ldap_auto_create=False,
                              ldap_email_trusted=False)
uid = auth.create_user("chefin", email="boss@example.com")       # proof on the account: yes
assert auth.store.get_user(uid)["email_verified"] == 1, "precondition: the account is proven"
auth.ldap = FakeLDAP({"chefin": {"password": "x", "email": "boss@example.com", "groups": []}})
assert c.post("/auth/login", data={"username": "chefin", "password": "x"},
              follow_redirects=False).status_code == 303        # login via the directory
assert not auth.get_user(uid)["is_admin"], \
    "the login route no longer passes \"no proof\" through — LDAP promotes again"
ok("B-umgehung-10: lock 1 on its own — the login route passes \"no proof\" through, even for a proven account")
# Counter-check: Without this pass-through (`email_bestaetigt=None`) the same note promotes
# immediately — this measures that the route REALLY decided above and nothing else.
assert auth._maybe_promote_admin(auth.get_user(uid), faktor="password") is True, \
    "nothing promotes even without the pass-through — then the check above measures nothing"
ok("... counter-check: without the pass-through the note on the account promotes immediately")
os.remove(db)

# ---------- R4-12: a directory identifier does not occupy a local one ----------
# Username and e-mail are ONE identifier space (`find_user` searches both columns). The
# cross-check sits in `create_user` and thus also hits auto-create from LDAP — and
# it must arrive here as a clean rejection, not as a 500 in the middle of the sign-in.
# The second case has ended BEFORE creation since the review round of 2026-09-27 (p1-d): The identifier
# `chef@example.com` belongs to one account locally, the directory entry led to another —
# `ldap_kennung_abgewiesen grund=kennung_zweier_konten` instead of `ldap_ident_taken`. The result stays.
for was, verzeichnis, kennung, ereignis in (
        ("deren Adresse lokal schon Kennung ist", {"password": "x", "email": "chef@example.com"}, "eve",
         "ldap_ident_taken"),
        ("deren Name lokal schon Adresse ist", {"password": "x", "email": "eve@example.com"}, "chef@example.com",
         "ldap_kennung_abgewiesen")):
    # With a trusted source: Only then does the address enter the account at all (default since 2026-09-25:
    # not trusted — then it occupies nothing anyway).
    db, auth, c = baue_ohne_admin(ldap_email_trusted=True)
    lokal = auth.create_user("chef", password="lokal12345", email="chef@example.com")
    auth.ldap = FakeLDAP({kennung: dict(verzeichnis, groups=[])})
    r = c.post("/auth/login", data={"username": kennung, "password": "x"}, follow_redirects=False)
    assert r.status_code == 401, f"HTTP {r.status_code} — 303 would be an occupied identifier, 500 a defect"
    assert auth.store.get_user_by_name(kennung) is None, "the account was created despite the rejection"
    assert (auth.find_user("chef@example.com") or {})["id"] == lokal, "the identifier was taken over"
    assert any(z["event"] == ereignis for z in auth.store.recent_audit(20)), \
        "no audit entry — the rejection is invisible"
    ok(f"R4-12: a directory identity, {was}, creates no account (401, no 500)")
    os.remove(db)

# Counter-check: free identifiers still create the account.
db, auth, c = baue_ohne_admin()
auth.create_user("chef", password="lokal12345", email="chef@example.com")
auth.ldap = FakeLDAP({"neu": {"password": "x", "email": "neu@example.com", "groups": []}})
r = c.post("/auth/login", data={"username": "neu", "password": "x"}, follow_redirects=False)
assert r.status_code == 303 and auth.store.get_user_by_name("neu") is not None, r.status_code
ok("... with free identifiers LDAP still creates the account")
os.remove(db)

# ---------- F-28: referrals are never followed ----------
# ldap3 follows a `SearchResultDone resultCode=10 (referral)` on its own and binds again
# on the host named in the RESPONSE with the same credentials. A taken-over directory
# — or, on a plaintext connection, any eavesdropper — thereby got the DN and password of the
# service account or the password of the person signing in handed over for free. This is reproduced with
# two real LDAP servers on loopback: A is the configured directory and answers with
# a referral to B, B records what arrives at it.
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
    """Read (messageID, protocolOp tag) from an LDAPMessage."""
    i = 1
    if daten[i] & 0x80:
        i += 1 + (daten[i] & 0x7F)
    else:
        i += 1
    assert daten[i] == 0x02, "no INTEGER at the expected position"
    n = daten[i + 1]
    mid = int.from_bytes(daten[i + 2:i + 2 + n], "big")
    return mid, daten[i + 2 + n]


def antwort(mid, op_tag, inhalt):
    return tlv(0x30, tlv(0x02, mid.to_bytes(1, "big")) + tlv(op_tag, inhalt))


def bind_ok(mid):
    return antwort(mid, 0x61, tlv(0x0A, b"\x00") + tlv(0x04, b"") + tlv(0x04, b""))


def suche_fertig(mid, uri=None):
    """SearchResultDone — with a referral (resultCode 10) or simply successful (0)."""
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
    """Server A: accept bind, answer search with/without referral."""
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
            else:                                  # unbind etc. → end
                break
        conn.close()
    except Exception as e:
        gesehen.append(f"fehler: {e!r}")


def fremder_host(sock, eimer):
    """Server B: only record what comes in."""
    try:
        conn, _ = sock.accept()
        conn.settimeout(8)
        eimer.append(conn.recv(8192))
        conn.close()
    except Exception:
        eimer.append(b"")


def aufbau(verweis=True):
    """Start both servers; returns (port_a, gesehen_a, eimer_b, sockets)."""
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
    # (a) Search bind of the service account: A refers to B → NOTHING may arrive at B.
    pa, gesehen, eimer, socks = aufbau()
    cfg_svc = TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True,
        ldap_url=f"ldap://127.0.0.1:{pa}", ldap_bind_dn=SVC_DN, ldap_bind_password=SVC_PW,
        ldap_user_base="ou=people,dc=example,dc=com", ldap_user_filter="(uid={username})")
    # While at it, also measure that the discarded referral writes a log line — here against
    # a REAL ldap3, not against the stub further below (only that proves the referral
    # really appears in `Connection.result` and not merely in our assumption of it).
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
        f"real ldap3: the discarded referral stayed silent: {_puffer.getvalue()[:200]!r}"
    time.sleep(0.5)
    beute = eimer[0] if eimer else b""
    assert SVC_DN.encode() not in beute, f"bind DN of the service account went to the referral host: {beute[:120]!r}"
    assert SVC_PW.encode() not in beute, f"password of the service account went to the referral host: {beute[:120]!r}"
    assert beute == b"", f"the referral host was contacted at all: {beute[:120]!r}"
    for s in socks:
        s.close()
    ok("Referral on the search bind: service account credentials do not reach the foreign host")

    # (b) User bind (direct DN): the referral arrives on the attribute search that runs on the
    #     connection with the PASSWORD OF THE PERSON SIGNING IN.
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
    # On this path too the referral must not stay silent: Without the attributes
    # e-mail, name and groups are missing — with `ldap_allowed_groups` that is a rejection without reason.
    assert "Attribut-Suche" in _puffer_b.getvalue(), \
        f"the referral on the attribute search stayed silent: {_puffer_b.getvalue()[:200]!r}"
    time.sleep(0.5)
    beute = eimer[0] if eimer else b""
    assert b"NUTZER-GEHEIM-456" not in beute, f"user password went to the referral host: {beute[:120]!r}"
    assert beute == b"", f"the referral host was contacted at all: {beute[:120]!r}"
    assert info and info["username"] == "alice"   # the bind confirmed the password
    for s in socks:
        s.close()
    ok("Referral on the attribute search: the password of the person signing in stays with the directory")

    # (c) Counter-check without referral: the normal path works unchanged.
    pa, gesehen, eimer, socks = aufbau(verweis=False)
    cfg_ok = TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True,
        ldap_url=f"ldap://127.0.0.1:{pa}",
        ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com")
    info = LDAPClient(cfg_ok).authenticate("alice", "richtig")
    assert info and info["username"] == "alice" and info["name"] == "alice", info
    assert "0x60" in gesehen and "0x63" in gesehen, gesehen   # bind AND search really ran
    for s in socks:
        s.close()
    ok("without referral: bind + attribute search against a real server still go through")
else:                                              # pragma: no cover
    print("  – referral test against real servers skipped (ldap3 missing)")

# The guarantee itself — independent of whether the extra is installed: EVERY connection this
# module opens switches referral chasing off, and the server allows no
# referral host. Measured with a substituted ldap3: If one of the two parameters
# is dropped, this check is red, even when no directory is anywhere near.
def stub_ldap3(mitschrift, leer=False, result=None):
    """Substituted ldap3. `leer=True` + `result=…` simulates the response of a directory
    that answers the search with a REFERRAL instead of entries."""
    mod = types.ModuleType("ldap3")
    mod.NONE, mod.BASE = "NONE", "BASE"
    # The stub reproduces what the code uses from ldap3 — since F-12 also `Tls` and the
    # AUTO_BIND constants. If they were missing, the suite would test a version of the module that does not
    # exist, and the hardening step would run into nothing here.
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

        def open(self):
            pass     # `authenticate` explicitly opens the user connection before the bind

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
assert len(verbindungen) == 3, f"expected: search bind + two user binds, was {len(verbindungen)}"
assert all(kw.get("auto_referrals") is False for kw in verbindungen), verbindungen
assert server and all(kw.get("allowed_referral_hosts") == [] for kw in server), server
ok("every connection sets auto_referrals=False, every server allowed_referral_hosts=[]")

# ---------- A-regression-9: the discarded referral must not be SILENT ----------
# The F-28 fix has a price: With `auto_referrals=False`, a search that the directory
# answers by referral ends without result — `authenticate()` returns None, and the app shows
# "wrong password". Whoever searches across several AD domains saw this for EVERY user after the update
# and had nothing pointing to the cause: The Global Catalog hint was only in the source code
# and in the CHANGELOG. Now the case writes a line to the security log.
import io as _io, logging as _logging          # noqa: E402
from tinysesam.security import seclog as _seclog  # noqa: E402

# The referral address comes from a THIRD PARTY: a line break in it would be an additional,
# freely invented line in exactly the log that fail2ban reads (log injection).
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
    # Counter-check: the same empty search WITHOUT referral is an ordinary "account does not exist"
    # and must not flood the log.
    sys.modules.update(stub_ldap3([], leer=True, result={"result": 0, "referrals": []}))
    _still = _mit_seclog(lambda: LDAPClient(_cfg_verweis).authenticate("alice", "egal"))
finally:
    for name, mod in _vorher.items():
        if mod is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = mod

assert "VERWEIS" in _text and "referral" in _text, f"no hint of the referral: {_text[:200]!r}"
# The host is checked with word boundaries, not by substring: `x-fremd.example.com.evil`
# would contain the name too, but would be a different host (CodeQL py/incomplete-url-substring-
# sanitization — a test guarantee here, but the same trap).
import re as _re_verweis  # noqa: E402
assert _re_verweis.search(r"(?<![\w.-])fremd\.example\.com(?![\w.-])", _text), \
    f"the referred host is missing: {_text[:200]!r}"
assert "Global Catalog" in _text and "3268" in _text, f"no operations hint: {_text[:200]!r}"
assert "user=alice" in _text, _text[:200]
assert len(_text.strip().splitlines()) == 1, f"the referral inserted a line: {_text!r}"
assert "ip=203.0.113.9" not in _text, f"log injection via the referral address: {_text!r}"
assert _still.strip() == "", f"an ordinary empty search reports itself: {_still[:120]!r}"
ok("discarded referral: one log line with host and Global Catalog hint (line break defused)")

# Side finding on F-28: ldap3 rejects a service account DN without password; the error is swallowed in
# the login and looks like a wrong password to every user. Hence the
# combination is now caught already when the configuration is built, not only in operation.
from tinysesam.konfigpruefung import pruefe

_gemeinsam = dict(db_path=":memory:", ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
                  ldap_user_base="ou=people,dc=example,dc=com")
_fehler, _warn = pruefe(TinySesamConfig(ldap_bind_dn=SVC_DN, **_gemeinsam))
assert any("ldap_bind_password" in w for w in _warn), _warn
assert not _fehler, _fehler
_, _warn_ok = pruefe(TinySesamConfig(ldap_bind_dn=SVC_DN, ldap_bind_password=SVC_PW, **_gemeinsam))
assert not any("ldap_bind_password" in w for w in _warn_ok), _warn_ok
_, _warn_anon = pruefe(TinySesamConfig(**_gemeinsam))          # anonymous search stays silent
assert not any("ldap_bind_password" in w for w in _warn_anon), _warn_anon
ok("ldap_bind_dn without ldap_bind_password is reported at setup, not only at login")

# ---------- F-12: the transport ----------
# Three defects at once: The default was plaintext, the certificate was never verified, and the
# service account bound BEFORE StartTLS encrypted the line — its password was thus
# already on the network. An eavesdropper needed no attack, only patience.
_mit12 = []
_vorher12 = {n: sys.modules.get(n) for n in ("ldap3", "ldap3.utils", "ldap3.utils.conv", "ldap3.utils.dn")}
sys.modules.update(stub_ldap3(_mit12))
try:
    # (a) TLS object with certificate verification goes to the server — before, there was none at all.
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldaps://dir.example.com",
                               ldap_user_dn_template="uid={username},dc=x")).authenticate("alice", "pw")
    _tls_kw = [kw for art, kw in _mit12 if art == "Tls"]
    assert _tls_kw, f"no Tls object built: {_mit12[:3]}"
    import ssl as _ssl
    assert _tls_kw[0]["validate"] == _ssl.CERT_REQUIRED, _tls_kw[0]
    _srv_kw = [kw for art, kw in _mit12 if art == "Server"]
    assert _srv_kw and _srv_kw[0].get("tls") is not None, _srv_kw
    ok("F-12: the server gets a TLS object with certificate verification")

    # (b) A custom CA file is passed through.
    _mit12.clear()
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldaps://dir.example.com", ldap_tls_ca_file="/etc/ssl/eigene.pem",
                               ldap_user_dn_template="uid={username},dc=x")).authenticate("alice", "pw")
    assert [kw for art, kw in _mit12 if art == "Tls"][0]["ca_certs_file"] == "/etc/ssl/eigene.pem"
    ok("F-12: a custom CA file is passed through")

    # (c) Can be switched off — but then explicitly without verification, not secretly.
    _mit12.clear()
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldaps://dir.example.com", ldap_tls_verify=False,
                               ldap_user_dn_template="uid={username},dc=x")).authenticate("alice", "pw")
    assert [kw for art, kw in _mit12 if art == "Tls"][0]["validate"] == _ssl.CERT_NONE
    ok("F-12: ldap_tls_verify=False switches the check off (and is reported at setup)")

    # (d) The core: The service account binds only AFTER the TLS upgrade.
    _mit12.clear()
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldap://dir.example.com", ldap_start_tls=True,
                               ldap_bind_dn="cn=svc,dc=x", ldap_bind_password="geheim",
                               ldap_user_base="dc=x")).authenticate("alice", "pw")
    _conns = [kw for art, kw in _mit12 if art == "Connection"]
    assert _conns, _mit12
    assert _conns[0].get("auto_bind") == "TLS_BEFORE_BIND", \
        f"the service account binds before the TLS upgrade: auto_bind={_conns[0].get('auto_bind')!r}"
    ok("F-12: the service account binds only after the TLS upgrade, not before")

    # Counter-check: without StartTLS there is nothing to upgrade — then no TLS_BEFORE_BIND.
    _mit12.clear()
    LDAPClient(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                               passkey_enabled=False, ldap_enabled=True,
                               ldap_url="ldaps://dir.example.com",
                               ldap_bind_dn="cn=svc,dc=x", ldap_bind_password="geheim",
                               ldap_user_base="dc=x")).authenticate("alice", "pw")
    assert [kw for art, kw in _mit12 if art == "Connection"][0].get("auto_bind") == "NO_TLS"
    ok("F-12: with ldaps:// the line is already encrypted — no additional upgrade")
finally:
    for n, m in _vorher12.items():
        if m is None:
            sys.modules.pop(n, None)
        else:
            sys.modules[n] = m

# And the configuration check catches plaintext operation when it is built.
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
ok("F-12: plaintext without explicit permission is a setup error, not an operational problem")

# ---------- F-11: the mapping hangs on a stable identifier, not on the name ----------
# A username is not forgery-proof. Whoever renames in the directory or re-creates a deleted
# account under the same name got, up to 0.19.0, the same local account including its
# roles — without knowing the local password.
db11, auth11, c11 = build(ldap_auto_create=True)

# (1) New account: is created AND bound.
auth11.ldap = FakeLDAP({"alice": {"password": "pw", "id": "uuid-alice", "email": "a@corp"}})
assert auth11._check_ldap("alice", "pw") is not None
_uid_a = auth11.store.get_user_by_name("alice")["id"]
assert auth11.store.get_federated_kennung("ldap", _uid_a) == "uuid-alice"
ok("F-11: a newly created account is bound to the directory's identifier")

# (2) Rename in the directory: same identifier, new name → same account.
auth11.ldap = FakeLDAP({"alice.neu": {"password": "pw", "id": "uuid-alice"}})
_u = auth11._check_ldap("alice.neu", "pw")
assert _u is not None and _u["id"] == _uid_a, f"renaming resulted in a different account: {_u}"
assert auth11.store.get_user_by_name("alice.neu") is None, "a second account was created"
ok("F-11: a rename in the directory is not an account switch")

# (3) THE ATTACK: new identifier under the old name → rejected.
auth11.ldap = FakeLDAP({"alice": {"password": "pw", "id": "uuid-FREMD"}})
assert auth11._check_ldap("alice", "pw") is None, \
    "a new directory account under the same name took over the local account"
assert any(e["event"] == "ldap_kennung_wechsel" for e in auth11.store.recent_audit(limit=10))
ok("F-11: a new directory account under the old name does NOT inherit the local account")

# (4) Existing case: an account without a binding is re-bound at the next login (PO decision).
_uid_b = auth11.create_user("bestand")
assert auth11.store.get_federated_kennung("ldap", _uid_b) is None
auth11.ldap = FakeLDAP({"bestand": {"password": "pw", "id": "uuid-bestand"}})
assert auth11._check_ldap("bestand", "pw") is not None
assert auth11.store.get_federated_kennung("ldap", _uid_b) == "uuid-bestand"
assert any(e["event"] == "ldap_kennung_gebunden" for e in auth11.store.recent_audit(limit=10))
ok("F-11: an existing account is re-bound at the next login — once, with an audit line")

# …and afterwards the guard from (3) also applies to this account.
auth11.ldap = FakeLDAP({"bestand": {"password": "pw", "id": "uuid-anders"}})
assert auth11._check_ldap("bestand", "pw") is None
ok("F-11: …afterwards this account is protected against the name change too")

# The operator can release the binding if the directory was really migrated.
assert auth11.federation_unbind("ldap", _uid_b) == 1
assert auth11._check_ldap("bestand", "pw") is not None
assert auth11.store.get_federated_kennung("ldap", _uid_b) == "uuid-anders"
ok("F-11: the operator releases the binding — a deliberate step, not a side effect")

# Without an identifier it stays with the name (legacy directories), but this is logged.
db11b, auth11b, c11b = build(ldap_auto_create=True)
auth11b.ldap = FakeLDAP({"ohne": {"password": "pw"}})     # no "id"
import io as _io11, logging as _log11                                      # noqa: E402
from tinysesam import security as _sec11                                   # noqa: E402
_sec11.einmal_melden_zuruecksetzen()
_puffer11 = _io11.StringIO()
_haken11 = _log11.StreamHandler(_puffer11)
_sec11.seclog.addHandler(_haken11)
try:
    assert auth11b._check_ldap("ohne", "pw") is not None
finally:
    _sec11.seclog.removeHandler(_haken11)
assert "keine stabile Kennung" in _puffer11.getvalue(), _puffer11.getvalue()[:200]
ok("F-11: a directory without a stable identifier reports itself but locks nobody out")

# …unless the operator demands one.
db11c, auth11c, c11c = build(ldap_auto_create=True, federation_require_stable_id=True)
auth11c.ldap = FakeLDAP({"ohne": {"password": "pw"}})
assert auth11c._check_ldap("ohne", "pw") is None
ok("F-11: federation_require_stable_id=True rejects a sign-in without identifier")

# A-4 (attack on H-4): Without a stable identifier nothing was ever bound — the LDAP account counted as local
# and got a reset link. The new local password then overrode the directory, even if the
# account was locked there. Here via the REAL login path, not via a binding made by hand.
db11d, auth11d, c11d = build(ldap_auto_create=True, password_reset_enabled=True,
                             base_url="https://auth.example.com")
_post11d = []
auth11d.set_mailer(lambda to, s, t, html=None: _post11d.append(to))
auth11d.ldap = FakeLDAP({"bob": {"password": "ldappw", "email": "bob@example.com"}})   # no "id"
assert c11d.post("/auth/login", data={"username": "bob", "password": "ldappw"},
                 follow_redirects=False).status_code == 303
_uid_bob = auth11d.store.get_user_by_name("bob")["id"]
assert auth11d.federated_only(_uid_bob), "LDAP account without identifier counts as local"
c11d.get("/auth/logout")
# The sign-in sends (address not trusted) a confirmation link — only the reset is measured here.
auth11d._hinweis_ausgang.abwarten()
_post11d.clear()
assert c11d.post("/auth/forgot", data={"email": "bob@example.com"}).status_code == 200
assert _post11d == [], f"LDAP account without identifier got a reset link: {_post11d}"
ok("A-4: an LDAP account without a stable identifier gets no reset link via the real login path")
# If a real identifier arrives later, it replaces the placeholder (re-binding, not an identifier change).
auth11d.ldap = FakeLDAP({"bob": {"password": "ldappw", "id": "uuid-bob"}})
assert auth11d._check_ldap("bob", "ldappw") is not None, "the placeholder blocks the real identifier"
assert auth11d.store.get_federated_kennung("ldap", _uid_bob) == "uuid-bob"
# An identifier in placeholder form from the directory is rejected — it would otherwise hit the
# account whose ID it names.
_adm11d = auth11d.store.get_user_by_name("admin")["id"]
auth11d.store.link_federated("ldap", f"{auth11d._OHNE_KENNUNG}{_adm11d}", _adm11d, 0)
auth11d.ldap = FakeLDAP({"mallory": {"password": "m", "id": f"{auth11d._OHNE_KENNUNG}{_adm11d}"}})
assert auth11d._check_ldap("mallory", "m") is None, "placeholder identifier took over a foreign account"
ok("A-4: real identifier replaces the placeholder; placeholder form from the directory rejected")

for _d in (db11, db11b, db11c, db11d):
    os.remove(_d)

# ---------- F-19: groups from the directory are no longer compared as a substring ----------
# Up to 0.20.0, LDAP ALWAYS compared by substring, `group_match` had no effect: `admin` matched
# `cn=nicht-admin,…`, `staff` matched `cn=staffextern,…`. Whoever may name a group in the directory
# (in many AD environments every department head) thereby got role and admin flag.
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
assert auth19._check_ldap("eve", "x") is None, "staff does not match cn=staffextern"
assert any(z["event"] == "ldap_group_denied" and z["username"] == "eve"
           for z in auth19.store.recent_audit(20)), "the rejection at the group gate is silent"
ok("F-19: ldap_allowed_groups=['staff'] does not let cn=staffextern through (and says so in the audit log)")
_mia = auth19._check_ldap("mia", "x")
assert _mia is not None and not _mia["is_admin"], "admin matches cn=nicht-admin"
assert auth19.store.get_roles(_mia["id"]) == [], auth19.store.get_roles(_mia["id"])
ok("F-19: 'admin' and 'cn=redaktion' match neither cn=nicht-admin nor cn=redaktion-alt")
_bob = auth19._check_ldap("bob", "x")
assert _bob is not None and _bob["is_admin"], "the exact CN match must still apply"
assert auth19.store.get_roles(_bob["id"]) == ["redaktion"], auth19.store.get_roles(_bob["id"])
ok("F-19: the usual key ('staff', 'cn=redaktion') still applies — case does not matter")
os.remove(db19)

# The explicit return to the old comparison remains possible — now the switch takes effect.
db19b, auth19b, _ = build(ldap_allowed_groups=["staff"], group_match="substring")
auth19b.ldap = FakeLDAP({"eve": {"password": "x", "id": "e1",
                                 "groups": ["cn=staffextern,ou=groups,dc=corp"]}})
assert auth19b._check_ldap("eve", "x") is not None
ok("F-19: group_match='substring' explicitly brings back the substring comparison")
os.remove(db19b)

from tinysesam.manager import gruppe_passt  # noqa: E402
assert gruppe_passt("cn=a\\,b", "cn=a\\,b,ou=g,dc=x", dn=True), "escaped comma does not split the DN"
assert not gruppe_passt("a", "cn=a\\,b,ou=g,dc=x", dn=True)
assert gruppe_passt("cn=staff,ou=groups,dc=corp", "CN=Staff, OU=Groups, DC=corp", dn=True)
assert not gruppe_passt("staff", "cn=staff,ou=g", dn=False), "without dn=True it stays with the exact text"
assert not gruppe_passt("", "cn=x", dn=True)
ok("F-19: gruppe_passt splits DNs at unescaped commas, compares whole DN/first RDN/value")

# A-3 (attack on F-19): The README example `{"cn=admins,ou=g": "__admin__"}` is a partial DN.
# After the first fix it no longer matched `cn=admins,ou=g,dc=example,dc=com` — admin mapping silently
# gone, with ldap_allowed_groups every user rejected.
assert gruppe_passt("cn=admins,ou=g", "cn=admins,ou=g,dc=example,dc=com", dn=True)
assert gruppe_passt("CN=Admins, OU=G", "cn=admins,ou=g,dc=example,dc=com", dn=True)
assert not gruppe_passt("ou=g", "cn=admins,ou=g,dc=example,dc=com", dn=True), "only from the front"
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
    _ada = auth19c._check_ldap("ada", "x")
finally:
    _sec19.seclog.removeHandler(_haken19)
assert _ada is not None, "README key as ldap_allowed_groups rejects everyone"
assert _ada["is_admin"], "README key as admin mapping does not apply"
assert auth19c.store.get_roles(_ada["id"]) == [], "substring 'ou=g' must not match"
# The key that would only match as a substring does not silently drop out: one line in the log.
assert "'ou=g'" in _puffer19.getvalue() and "Teilstring" in _puffer19.getvalue(), _puffer19.getvalue()[:300]
assert "cn=admins,ou=g'" not in _puffer19.getvalue(), "a key that applies must not warn"
ok("A-3: partial DN from the front (README example) applies again; a pure substring key reports itself")
os.remove(db19c)

# ---------- F-23: a directory outage is not a failed attempt ----------
# Up to 0.20.0, every error in `authenticate()` ended as None, i.e. as "wrong password": a
# failed attempt against account and IP, `failed login` for fail2ban. After a few minutes of outage
# exactly the users who had done nothing wrong were locked out.
from tinysesam.ldap_ import AUSFALL_PAUSE_SEK, AusfallMerker, VerzeichnisNichtErreichbar  # noqa: E402
from tinysesam import ldap_ as _ldap_mod                    # noqa: E402


class AusfallLDAP:
    def authenticate(self, username, password):
        raise VerzeichnisNichtErreichbar("LDAP-Verzeichnis ldap://dummy nicht benutzbar: Test")


db23, auth23, c23 = build()
auth23.ldap = AusfallLDAP()
# After an outage, the login does not ask the directory for one pause (outage flag, see
# below); the flag's clock is set here so that the counter-check can let the pause expire.
_uhr23 = [1000.0]
auth23._ldap_ausfall = AusfallMerker(uhr=lambda: _uhr23[0])
import io as _io23, logging as _log23                     # noqa: E402
from tinysesam.security import seclog as _seclog23       # noqa: E402
_puffer23 = _io23.StringIO()
_haken23 = _log23.StreamHandler(_puffer23)
_seclog23.addHandler(_haken23)
try:
    antworten23 = [c23.post("/auth/login", data={"username": "alice", "password": "egal"})
                   for _ in range(auth23._sec("max_login_attempts") + 2)]
finally:
    _seclog23.removeHandler(_haken23)
assert all(a.status_code == 503 for a in antworten23), [a.status_code for a in antworten23]
assert "nicht erreichbar" in antworten23[0].text, antworten23[0].text[:300]
assert auth23.store.count_fails(0, username="alice") == 0, "the outage was booked as a failed attempt"
assert not auth23._is_locked("alice", "testclient"), "an outage locks the account"
assert "failed login" not in _puffer23.getvalue(), "fail2ban would take an outage for an attack"
assert "LDAP nicht erreichbar" in _puffer23.getvalue(), _puffer23.getvalue()[:300]
assert any(z["event"] == "ldap_unavailable" for z in auth23.store.recent_audit(20))
ok("F-23: directory outage → 503, no failed attempt, no lockout, no 'failed login', own audit line")
# Counter-check: the same route with a reachable directory and a wrong password counts —
# as soon as the pause after the outage has expired and the login asks again.
auth23.ldap = FakeLDAP({"alice": {"password": "richtig"}})
_uhr23[0] += AUSFALL_PAUSE_SEK + 1
assert c23.post("/auth/login", data={"username": "alice", "password": "falsch"}).status_code == 401
assert auth23.store.count_fails(0, username="alice") == 1
ok("F-23: …a real wrong password remains a failed attempt")
os.remove(db23)

# A-1 (attack on F-23): During the outage, the wrong LOCAL password was also
# not booked — against the local admin, the emergency account, guessing was possible without limit (distributed
# across IPs only the IP rate limit applied), and the correct password afterwards got through despite
# max_login_attempts.
db23a, auth23a, c23a = build()
auth23a.ldap = AusfallLDAP()
_max23a = auth23a._sec("max_login_attempts")
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
    "wrong local password during the outage was not booked"
assert auth23a._is_locked("admin", "testclient"), "local admin can be guessed without limit during the outage"
assert "failed login" in _puffer23a.getvalue(), "fail2ban does not see the guessing at the local account"
_r23a = c23a.post("/auth/login", data={"username": "admin", "password": "lokalpw"}, follow_redirects=False)
assert _r23a.status_code == 429, f"correct password got through after {_max23a} failed attempts: {_r23a.status_code}"
# The directory share stays excused: the LDAP account without a local password does not count.
c23a.post("/auth/login", data={"username": "alice", "password": "x"})
assert auth23a.store.count_fails(0, username="alice") == 0
ok("A-1: outage excuses only the directory — a wrong LOCAL password counts and locks")
os.remove(db23a)

# ---------- T-13 integration: pre-booked attempts do not hang until the timeout ----------
# The login books every attempt IN ADVANCE as a failed attempt (R7-2) and takes it back on an outage
# (F-23) — but only when `VerzeichnisNichtErreichbar` arrives. A directory that
# drops packets answers only after the timeout (10 s). Until then every hanging sign-in counted for
# account, pair and address: 15 colleagues behind one NAT address, and the local emergency admin
# got 429 with the CORRECT password; every further rejection wrote `failed login … reason=
# lockout_ip`, and fail2ban banned the address. And not just once, but on every attempt
# during the whole outage. Now the login remembers the outage: Afterwards 503 comes immediately,
# without asking the directory again. (Mutation probe: remove the call in `check_ldap`
# `self._ldap_ausfall.zugang()` → the burst hangs, the directory is asked on every attempt
# again → red. Until G9 the admin also got 429 here; since then he waits until the
# pending pre-bookings are decided — tests/test_vorbuchung_schwebe.py measures that.)
from concurrent.futures import ThreadPoolExecutor as _Pool24  # noqa: E402

HAENGT24 = 2.0


class HaengendesLDAP:
    """A directory that drops packets: every query hangs until the timeout, then outage."""

    def __init__(self):
        self.fragen = 0
        self._zaehler = threading.Lock()

    def authenticate(self, username, password):
        with self._zaehler:
            self.fragen += 1
        time.sleep(HAENGT24)
        raise VerzeichnisNichtErreichbar("LDAP-Verzeichnis ldap://dummy nicht benutzbar: timed out")


db24, auth24, c24 = build()
auth24.set_security("rate_limit_max", 1000)          # a 429 must come from the lockout
haengt24 = HaengendesLDAP()
auth24.ldap = haengt24
NAT24 = ("198.51.100.7", 40000)
SCHWELLE24 = auth24._sec("max_login_attempts") * auth24._sec("ip_attempt_factor")


def _anmelden24(name, pw="x"):
    return TestClient(c24.app, client=NAT24).post(
        "/auth/login", data={"username": name, "password": pw}, follow_redirects=False).status_code


_puffer24 = _io23.StringIO()
_haken24 = _log23.StreamHandler(_puffer24)
_seclog23.addHandler(_haken24)
try:
    # (1) The first attempt discovers the outage. It hangs until the timeout — this one window
    # remains, because before that nobody knows that the directory is gone.
    _t0 = time.monotonic()
    assert _anmelden24("kollege0") == 503
    assert time.monotonic() - _t0 >= HAENGT24 * 0.9, "precondition: the first query did not hang"
    # (2) During the outage: the whole office behind the NAT address — as many as the
    # IP threshold, all within three fifths of the timeout —, then the local emergency admin
    # with the correct password. Without the flag, all attempts would still be pending at that time and fill
    # the IP threshold. Staggered, not all at once: A pre-booking now lives as long as
    # the local check and a few write accesses (some hundred milliseconds under load).
    # If more sign-ins than the IP threshold arrive AT THE SAME TIME, the lockout rejects some — that
    # is exactly R7-2 in normal operation and has nothing to do with the outage.
    _anzahl24 = SCHWELLE24
    _abstand24 = HAENGT24 * 0.6 / _anzahl24
    with _Pool24(max_workers=_anzahl24) as _pool24:
        _laufend24 = []
        for i in range(1, _anzahl24 + 1):
            _laufend24.append(_pool24.submit(_anmelden24, f"kollege{i}"))
            time.sleep(_abstand24)
        _schwebend24 = auth24.store.count_fails(0, ip=NAT24[0])
        _admin24 = _anmelden24("admin", "lokalpw")
        _kollegen24 = [f.result(timeout=30) for f in _laufend24]
    # (3) The impatient user who submits seven times on the hanging page.
    _klicks24 = [_anmelden24("alice") for _ in range(7)]
finally:
    _seclog23.removeHandler(_haken24)
assert _admin24 == 303, (f"the emergency admin cannot get in during the outage: {_admin24} "
                         f"({_schwebend24} pre-booked attempts of the address were pending)")
assert _kollegen24 == [503] * len(_kollegen24), f"colleagues during the outage: {sorted(set(_kollegen24))}"
assert _klicks24 == [503] * 7, f"impatient clicks: {_klicks24}"
assert haengt24.fragen == 1, f"during the pause the directory was asked again {haengt24.fragen - 1} times"
assert "failed login" not in _puffer24.getvalue(), \
    "fail2ban would take the outage for an attack: " + next(
        z for z in _puffer24.getvalue().splitlines() if "failed login" in z)
assert auth24.store.count_fails(0, ip=NAT24[0]) == 0, "failed attempts remained from the outage"
ok(f"F-23 × R7-2: 503 immediately after the first timeout — {len(_kollegen24)} colleagues, 7 clicks, "
   "the local admin gets in, no 'failed login'")

# After the pause EXACTLY ONE sign-in asks again (probe); all others keep getting 503 immediately
# until it is back — otherwise after every pause all those just knocking would hang again. If
# the directory answers again (even with "wrong password"), it is free. The change is reported, once
# each, not on every request. (Mutation probe: in `AusfallMerker.zugang` ignore the running probe
# (`if rest > 0:` instead of `if rest > 0 or self._probe:`) → during the probe everybody asks
# the directory → red; remove `merker.erreicht()` in `check_ldap` → the returned
# directory stays locked → red.)
_uhr24 = [5000.0]
auth24._ldap_ausfall = AusfallMerker(uhr=lambda: _uhr24[0])
haengt24.fragen = 0
_puffer24b = _io23.StringIO()
_haken24b = _log23.StreamHandler(_puffer24b)
_seclog23.addHandler(_haken24b)
try:
    assert _anmelden24("kollege0") == 503 and haengt24.fragen == 1      # outage discovered
    assert _anmelden24("kollege1") == 503 and haengt24.fragen == 1      # pause: not asked
    _uhr24[0] += AUSFALL_PAUSE_SEK + 1                                  # pause over
    with _Pool24(max_workers=2) as _pool24b:
        _probe24 = _pool24b.submit(_anmelden24, "kollege2")             # the probe hangs
        time.sleep(HAENGT24 / 4)
        _andere24 = [_anmelden24(f"kollege{i}") for i in range(3, 13)]
        _admin24b = _anmelden24("admin", "lokalpw")
        _probe_status24 = _probe24.result(timeout=30)
    assert haengt24.fragen == 2, \
        f"during the probe {haengt24.fragen - 2} further sign-ins asked the directory"
    assert _andere24 == [503] * 10 and _probe_status24 == 503, (_andere24, _probe_status24)
    assert _admin24b == 303, f"the local admin during the probe: {_admin24b}"
    # The directory is back: After the next pause the probe answers, afterwards everything runs normally.
    auth24.ldap = FakeLDAP({"alice": {"password": "richtig"}})
    _uhr24[0] += AUSFALL_PAUSE_SEK + 1
    assert _anmelden24("alice", "falsch") == 401, "the probe with a wrong password is a failed attempt"
    assert _anmelden24("alice", "richtig") == 303, "after the directory's return it stays locked"
finally:
    _seclog23.removeHandler(_haken24b)
_text24 = _puffer24b.getvalue()
assert _text24.count("LDAP-Verzeichnis nicht erreichbar (") == 1, _text24
assert _text24.count("LDAP-Verzeichnis wieder erreichbar") == 1, _text24
assert "failed login user=kollege" not in _text24, _text24
assert auth24.store.count_fails(0, username="alice") == 0, "the full login clears the failed attempt"
ok("…after the pause exactly one sign-in asks again; outage and return appear once each in the log")
os.remove(db24)

# Only the probe itself releases the probe's slot (`ausgefallen(war_probe=True)`). A
# straggler from the first window that only runs into its timeout during the probe reports
# `war_probe=False` — if it released the slot, the next sign-in would immediately ask in parallel to the
# running probe, and after every pause several attempts would hang again. (Mutation probe:
# in `AusfallMerker.ausgefallen` always release the slot (`self._probe = False` without
# `if war_probe`) → red.)
_uhr_n = [100.0]
_m_n = AusfallMerker(uhr=lambda: _uhr_n[0])
_m_n.ausgefallen(VerzeichnisNichtErreichbar("Test: timed out"))
_uhr_n[0] += AUSFALL_PAUSE_SEK + 1
assert _m_n.zugang() is True, "precondition: after the pause the next sign-in is the probe"
_m_n.ausgefallen(VerzeichnisNichtErreichbar("Test: Nachzügler"), war_probe=False)   # straggler
_uhr_n[0] += AUSFALL_PAUSE_SEK + 1
try:
    _m_n.zugang()
    _zweite_probe = True
except VerzeichnisNichtErreichbar as _e_n:
    _zweite_probe = False
    assert "fragt gerade nach" in str(_e_n), str(_e_n)
assert not _zweite_probe, "a straggler released the slot of the running probe — two probes at once"
_m_n.ausgefallen(VerzeichnisNichtErreichbar("Test: Probe gescheitert"), war_probe=True)
_uhr_n[0] += AUSFALL_PAUSE_SEK + 1
assert _m_n.zugang() is True, "after the end of the probe the next one asks again"
ok("Outage flag: a straggler does not release the slot of the running probe")

# If the probe ends with a DIFFERENT exception (programming error in our own client, missing extra),
# `check_ldap` must release its slot — otherwise nobody asks any more, and the LDAP sign-in
# returns 503 until restart, even with a healthy directory. (Mutation probe: in `check_ldap`
# remove the branch `except BaseException: if probe: merker.freigeben()` → red.)
class _LaunischesLDAP:
    modus = "weg"

    def authenticate(self, username, password):
        if self.modus == "weg":
            raise VerzeichnisNichtErreichbar("LDAP-Verzeichnis ldap://dummy nicht benutzbar: timed out")
        if self.modus == "kaputt":
            raise RuntimeError("unerwarteter Fehler im Client")
        if self.modus == "abgebrochen":
            raise _ldap_mod.AnfrageAbgebrochen("Test: Verbindung nach dem Bind vom Server beendet")
        return {"username": username, "email": None, "name": username, "groups": [], "id": "l-1"}


_auth_p = TinySesam(TinySesamConfig(db_path=":memory:", ldap_enabled=True, ldap_url="ldap://dummy",
                                    ldap_allow_plaintext=True, passkey_enabled=False, oidc_enabled=False))
_uhr_p = [100.0]
_auth_p._ldap_ausfall = AusfallMerker(uhr=lambda: _uhr_p[0])
_auth_p.ldap = _launisch = _LaunischesLDAP()
try:
    _auth_p._check_ldap("alice", "pw")
except VerzeichnisNichtErreichbar:
    pass   # the flag is armed afterwards — only that counts here
_uhr_p[0] += AUSFALL_PAUSE_SEK + 1
_launisch.modus = "kaputt"
try:
    _auth_p._check_ldap("alice", "pw")
    raise AssertionError("Vorbedingung: die Probe hätte mit RuntimeError enden müssen")
except RuntimeError:
    pass
_launisch.modus = "gesund"
try:
    _info_p = _auth_p._check_ldap("alice", "pw")
except VerzeichnisNichtErreichbar as _e_p:
    raise AssertionError(f"nach einer Probe mit fremder Ausnahme fragt niemand mehr nach: {_e_p}")
assert _info_p, _info_p
# The same if the probe only loses its own request (`AnfrageAbgebrochen`, see below): no
# proof of an outage, but none of the return either — the next sign-in asks again.
# (Mutation probe: in the branch `except AnfrageAbgebrochen` of `check_ldap` remove
# `merker.freigeben()` → red.)
_launisch.modus = "weg"
try:
    _auth_p._check_ldap("alice", "pw")
except VerzeichnisNichtErreichbar:
    pass   # the flag is armed afterwards — only that counts here
_uhr_p[0] += AUSFALL_PAUSE_SEK + 1
_launisch.modus = "abgebrochen"
try:
    _auth_p._check_ldap("alice", "pw")
    raise AssertionError("Vorbedingung: die Probe hätte abgebrochen werden müssen")
except _ldap_mod.AnfrageAbgebrochen:
    pass
_launisch.modus = "gesund"
try:
    _info_p = _auth_p._check_ldap("alice", "pw")
except VerzeichnisNichtErreichbar as _e_p:
    raise AssertionError(f"nach einer abgebrochenen Probe fragt niemand mehr nach: {_e_p}")
assert _info_p, _info_p
ok("Outage flag: if the probe ends with a foreign exception or an abort, the next one asks again")

# ---------- Follow-up T-13: an oversized sign-in does not take LDAP down silently ----------
# The flag armed on EVERY `VerzeichnisNichtErreichbar` — even when only this one
# request had failed. With its default `sockbuf_max_incoming=262143`, OpenLDAP ends the
# connection as soon as a bind PDU on the (still anonymous) session is larger; ldap3 reports this
# as a communication error. A password of 270 000 characters, submitted without signing in, thus gave
# every LDAP user 503 for 30 s — repeated every 2.5 s permanently, and it cost the attacker
# nothing (pre-booking taken back, no `failed login`). First lock: Whatever is longer than
# any real sign-in never reaches the directory at all and is a wrong password.
# (Mutation probe: in `check_ldap` remove the check `ldap_.eingabe_zu_lang` → the client
# is asked → red.)
class _MitschreibendesLDAP(FakeLDAP):
    def __init__(self, users):
        super().__init__(users)
        self.gefragt = []

    def authenticate(self, username, password):
        self.gefragt.append((len(username), len(password)))
        return super().authenticate(username, password)


db_g, auth_g, c_g = build()
auth_g.set_security("rate_limit_max", 1000)
auth_g.ldap = _mitschrift_g = _MitschreibendesLDAP({"alice": {"password": "richtig"}})
_puffer_g = _io23.StringIO()
_haken_g = _log23.StreamHandler(_puffer_g)
_seclog23.addHandler(_haken_g)
try:
    _gross = [TestClient(c_g.app, client=("203.0.113.66", 40000)).post(
        "/auth/login", data=daten, follow_redirects=False).status_code
        for daten in ({"username": "alice", "password": "x" * 270_000},
                      {"username": "n" * 270_000, "password": "x"})]
finally:
    _seclog23.removeHandler(_haken_g)
assert _mitschrift_g.gefragt == [], f"oversized inputs went to the directory: {_mitschrift_g.gefragt}"
assert _gross == [401, 401], f"oversized inputs: {_gross} (expected: like a wrong password)"
assert auth_g.store.count_fails(0, ip="203.0.113.66") == 2, "the oversized attempts do not count"
assert _puffer_g.getvalue().count("failed login") == 2, "fail2ban does not see the oversized attempts"
_r_g = TestClient(c_g.app, client=("192.0.2.10", 40000)).post(
    "/auth/login", data={"username": "alice", "password": "richtig"}, follow_redirects=False)
assert _r_g.status_code == 303, f"the correct sign-in afterwards: {_r_g.status_code}"
os.remove(db_g)
ok("oversized inputs do not go to the directory: 401, failed attempt, 'failed login' — LDAP stays open")

if HAT_LDAP3:
    # Against the REAL ldap3: a port on which nobody listens. The exception must come from the
    # library, not from our stub — otherwise the mapping of the error kinds
    # (`_ausfall_arten`) would be unmeasured.
    # The port stays BOUND, just without `listen()`: Connections are refused as with a
    # dead port, but no other process gets it in the meantime. Before, it was released right
    # away — if another suite was running alongside (the collective run starts them in parallel) and
    # got the same number for its stub server, ldap3 talked to THAT instead of to nobody.
    _s = socket.socket()
    _s.bind(("127.0.0.1", 0))
    _toter_port = _s.getsockname()[1]
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
        except VerzeichnisNichtErreichbar as _e_tot:
            _geworfen = True
            # A dead port affects the whole directory: The flag must arm.
            # (Mutation probe: in `authenticate` report every error as `AnfrageAbgebrochen` → red.)
            assert not isinstance(_e_tot, getattr(_ldap_mod, "AnfrageAbgebrochen", ())), \
                f"a dead port counts as an error of this request only: {_e_tot!r}"
        assert _geworfen, "a dead port ends as 'wrong password' again"
    _zweiter = socket.socket()
    _zweiter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        _zweiter.bind(("127.0.0.1", _toter_port))
        _belegt = False
    except OSError:
        _belegt = True
    finally:
        _zweiter.close()
    _s.close()
    assert _belegt, "the dead port was free during the probe — a parallel suite could have taken it"
    ok("F-23: real ldap3 against a dead port → VerzeichnisNichtErreichbar (direct and search bind)")
    # And a rejected password against a REAL server stays None, not outage.
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
            pass   # the client hung up — no error for this stub server

    threading.Thread(target=_lehnt_ab, args=(_sa,), daemon=True).start()
    assert LDAPClient(TinySesamConfig(
        db_path=":memory:", password_enabled=True, ldap_enabled=True,
        ldap_url=f"ldap://127.0.0.1:{_pa}", ldap_allow_plaintext=True,
        ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com")).authenticate(
        "alice", "falsch") is None
    _sa.close()
    ok("F-23: invalidCredentials from the real server stays None (failed attempt), no outage")

    # Second lock, against REAL ldap3 and a directory on loopback that behaves like slapd:
    # A PDU over its limit ends the connection without a response. The limit is set small here
    # so that an input BELOW the input limit breaks it — like any
    # future way of making a single request abort. If the directory aborts only this
    # one request (quickly, after the sign-in person's inputs had been sent), that is not an
    # outage of the directory: 503 for this request, the flag stays off, the next
    # sign-in asks normally. (Mutation probe: in `check_ldap` treat `AnfrageAbgebrochen` like any
    # outage (`merker.ausgefallen`) → alice gets 503 → red; in `authenticate` remove the
    # distinction (always `VerzeichnisNichtErreichbar`) → red.)
    def _tlv_lesen(d, i):
        tag = d[i]
        i += 1
        if d[i] & 0x80:
            k = d[i] & 0x7F
            n = int.from_bytes(d[i + 1:i + 1 + k], "big")
            i += 1 + k
        else:
            n = d[i]
            i += 1
        return tag, d[i:i + n], i + n

    class _MiniVerzeichnis:
        """LDAP directory on loopback with real PDUs. `grenze` like slapd's
        `sockbuf_max_incoming` (a larger PDU ends the connection without a response);
        `haengt=True`: accepts connections, reads along, never answers."""
        NUTZER = {b"uid=alice,ou=people,dc=example,dc=com": b"richtig"}

        def __init__(self, grenze=262143, haengt=False):
            self.grenze, self.haengt = grenze, haengt
            self.log, self.verbindungen = [], 0
            self._sock = socket.socket()
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("127.0.0.1", 0))
            self._sock.listen(32)
            self.port = self._sock.getsockname()[1]
            threading.Thread(target=self._annehmen, daemon=True).start()

        def _annehmen(self):
            while True:
                try:
                    conn, _ = self._sock.accept()
                except OSError:
                    return
                self.verbindungen += 1
                threading.Thread(target=self._sitzung, args=(conn,), daemon=True).start()

        def _mehr(self, conn, puffer):
            d = conn.recv(65536)
            if not d:
                raise EOFError
            return puffer + d

        def _sitzung(self, conn):
            puffer = b""
            try:
                while True:
                    while len(puffer) < 2 or (puffer[1] & 0x80 and len(puffer) < 2 + (puffer[1] & 0x7F)):
                        puffer = self._mehr(conn, puffer)
                    if puffer[1] & 0x80:
                        k = puffer[1] & 0x7F
                        n, kopf = int.from_bytes(puffer[2:2 + k], "big"), 2 + k
                    else:
                        n, kopf = puffer[1], 2
                    if kopf + n > self.grenze:
                        self.log.append(f"zu gross {kopf + n}")
                        return                      # connection closed, no response — like slapd
                    while len(puffer) < kopf + n:
                        puffer = self._mehr(conn, puffer)
                    pdu, puffer = puffer[:kopf + n], puffer[kopf + n:]
                    mid, op = zerlegen(pdu)
                    if self.haengt:
                        self.log.append(f"haengt {hex(op)}")
                        continue
                    if op == 0x60:
                        _, inhalt, _ = _tlv_lesen(pdu, 0)
                        _, _, j = _tlv_lesen(inhalt, 0)
                        _, bind, _ = _tlv_lesen(inhalt, j)
                        _, _, k = _tlv_lesen(bind, 0)
                        _, name, k = _tlv_lesen(bind, k)
                        _, pw, _ = _tlv_lesen(bind, k)
                        gut = self.NUTZER.get(name) == pw
                        self.log.append(f"bind {name.decode()} {'ok' if gut else 'falsch'}")
                        conn.sendall(antwort(mid, 0x61, tlv(0x0A, b"\x00" if gut else b"\x31")
                                             + tlv(0x04, b"") + tlv(0x04, b"")))
                    elif op == 0x63:
                        conn.sendall(suche_fertig(mid))
                    else:
                        return
            except (OSError, EOFError):
                pass   # stub server: the client hung up
            finally:
                conn.close()

        def schliessen(self):
            self._sock.close()

    def _echt_bauen(port):
        db = os.path.join(tempfile.mkdtemp(), "t.db")
        a = TinySesam(TinySesamConfig(
            csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False,
            oidc_enabled=False, cookie_secure=False, ldap_enabled=True,
            ldap_url=f"ldap://127.0.0.1:{port}", ldap_allow_plaintext=True,
            ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com"))
        a.set_security("rate_limit_max", 1000)
        anw = FastAPI()
        anw.include_router(a.router())
        return a, anw, db

    def _echt_anmelden(anw, name, pw, ip):
        return TestClient(anw, client=(ip, 40000)).post(
            "/auth/login", data={"username": name, "password": pw}, follow_redirects=False).status_code

    _v = _MiniVerzeichnis(grenze=900)
    _auth_v, _app_v, _db_v = _echt_bauen(_v.port)
    try:
        assert _echt_anmelden(_app_v, "alice", "richtig", "192.0.2.10") == 303, "precondition: alice gets in"
        _grenze_v = __import__("tinysesam.ldap_", fromlist=["x"])
        _lang_v = "x" * 1000                  # below the input limit, above the directory's PDU limit
        assert len(_lang_v) <= getattr(_grenze_v, "LDAP_PASSWORT_MAX", 10 ** 9), "precondition: input below the limit"
        _t_v = time.monotonic()
        _puffer_v = _io23.StringIO()
        _haken_v = _log23.StreamHandler(_puffer_v)
        _seclog23.addHandler(_haken_v)
        try:
            _abbruch_v = _echt_anmelden(_app_v, "bob", _lang_v, "203.0.113.66")
        finally:
            _seclog23.removeHandler(_haken_v)
        # Distinguishable in the security log — even after the reason is truncated to 64 characters.
        assert "grund=LDAP: nur diese Anfrage abgebrochen" in _puffer_v.getvalue(), _puffer_v.getvalue()
        assert "LDAP-Verzeichnis nicht erreichbar (" not in _puffer_v.getvalue(), "the flag reported"
        assert any(z.startswith("zu gross") for z in _v.log), f"precondition: no abort in the directory: {_v.log}"
        assert _abbruch_v == 503, f"the aborted request itself: {_abbruch_v}"
        _vorher_v = len(_v.log)
        _danach_v = [_echt_anmelden(_app_v, "alice", "richtig", f"192.0.2.{20 + i}") for i in range(3)]
        assert _danach_v == [303] * 3, \
            f"ONE aborted request takes down the LDAP sign-in of everyone: {_danach_v} ({_v.log[_vorher_v:]})"
        assert _v.log[_vorher_v:].count("bind uid=alice,ou=people,dc=example,dc=com ok") == 3, _v.log[_vorher_v:]
        assert time.monotonic() - _t_v < 5, "the abort hung"
    finally:
        _v.schliessen()
        os.remove(_db_v)
    ok("a single request that the directory aborts does not arm the flag")

    # The input limit also applies if someone uses `LDAPClient` directly: The directory does not see
    # the oversized input at all. (Mutation probe: in `LDAPClient.authenticate` remove the check
    # `eingabe_zu_lang` → the directory is asked → red.)
    _v2 = _MiniVerzeichnis()
    try:
        _cfg_v2 = TinySesamConfig(db_path=":memory:", password_enabled=True, ldap_enabled=True,
                                  ldap_url=f"ldap://127.0.0.1:{_v2.port}", ldap_allow_plaintext=True,
                                  ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com")
        assert LDAPClient(_cfg_v2).authenticate("alice", "richtig"), "precondition: the server answers"
        _vorher_v2 = _v2.verbindungen
        assert LDAPClient(_cfg_v2).authenticate("alice", "x" * 270_000) is None
        assert LDAPClient(_cfg_v2).authenticate("n" * 270_000, "richtig") is None
        time.sleep(0.2)
        assert _v2.verbindungen == _vorher_v2, f"oversized inputs reached the directory: {_v2.log}"
    finally:
        _v2.schliessen()
    ok("LDAPClient: oversized inputs do not reach the directory (None)")

    # The distinction hangs on the STEP, not merely on the error kind: If the directory ends
    # the connection already at StartTLS, ldap3 reports the same `LDAPSessionTerminatedByServerError`
    # as for the aborted bind — only that nothing from the person signing in has been sent by then. That is
    # an outage of the directory (e.g. a TLS front end without backend), not an abort of this
    # request. (Mutation probe: in `authenticate` treat connection and StartTLS already as
    # input step (`eingabe, seit = True, …` before `conn.open()`) → red.)
    _st, _pst = lauscher()

    def _schliesst_bei_starttls(sock):
        try:
            conn, _ = sock.accept()
            conn.settimeout(5)
            conn.recv(8192)                        # ExtendedRequest StartTLS — and close
            conn.close()
        except OSError:
            pass   # stub server: the client hung up

    threading.Thread(target=_schliesst_bei_starttls, args=(_st,), daemon=True).start()
    try:
        LDAPClient(TinySesamConfig(
            db_path=":memory:", password_enabled=True, ldap_enabled=True,
            ldap_url=f"ldap://127.0.0.1:{_pst}", ldap_start_tls=True, ldap_tls_verify=False,
            ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com")).authenticate("alice", "pw")
        _e_st = None
    except VerzeichnisNichtErreichbar as _e:
        _e_st = _e
    finally:
        _st.close()
    assert _e_st is not None, "precondition: the abort at StartTLS was not reported"
    assert not isinstance(_e_st, _ldap_mod.AnfrageAbgebrochen), \
        f"an abort at StartTLS (before any input) counts as an error of this request only: {_e_st!r}"
    ok("Abort already at StartTLS: outage of the directory, not merely of this request")

    # Counter-check: A directory that accepts and never answers (process hangs, backend
    # blocked) remains an outage of the WHOLE directory — even if it only hangs after
    # the user bind was sent. Otherwise every attempt would again hang until the timeout (F-23 ×
    # R7-2). The clocks are set small so that the test does not wait ten seconds.
    # (Mutation probe: in `authenticate` ignore the duration — report every error after the input was sent
    # as `AnfrageAbgebrochen` → the second sign-in asks again → red.)
    _ldap_mod_h = __import__("tinysesam.ldap_", fromlist=["x"])
    _alt_h = {n: getattr(_ldap_mod_h, n) for n in ("VERBINDUNGS_TIMEOUT", "HAENGER_SEK") if hasattr(_ldap_mod_h, n)}
    _ldap_mod_h.VERBINDUNGS_TIMEOUT, _ldap_mod_h.HAENGER_SEK = 1, 0.3
    _h = _MiniVerzeichnis(haengt=True)
    _auth_h, _app_h, _db_h = _echt_bauen(_h.port)
    try:
        _t_h = time.monotonic()
        assert _echt_anmelden(_app_h, "alice", "richtig", "192.0.2.10") == 503
        assert time.monotonic() - _t_h >= 0.9, "precondition: the first query did not hang until the timeout"
        assert any(z.startswith("haengt 0x60") for z in _h.log), f"precondition: the bind arrived: {_h.log}"
        _n_h = _h.verbindungen
        _t_h = time.monotonic()
        assert _echt_anmelden(_app_h, "alice", "richtig", "192.0.2.11") == 503
        assert _h.verbindungen == _n_h, "after a hang at the user bind the directory was asked again right away"
        assert time.monotonic() - _t_h < 0.9, "the second sign-in hung again"
    finally:
        for _n, _w in _alt_h.items():
            setattr(_ldap_mod_h, _n, _w)
        if "HAENGER_SEK" not in _alt_h:
            delattr(_ldap_mod_h, "HAENGER_SEK")
        _h.schliessen()
        os.remove(_db_h)
    ok("a directory that hangs at the user bind still arms the flag")

# ---------- F-29: LDAP and local sign-in are distinguishable in the audit log ----------
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
ok("F-29: login_ldap / login_lokal separate, a failed attempt names quelle=lokal+ldap")
os.remove(db29)
# Without LDAP the audit log stays as before — no new line for every local login.
db29b = os.path.join(tempfile.mkdtemp(), "t.db")
auth29b = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db29b, rp_name="Test",
                                    passkey_enabled=False, cookie_secure=False))
auth29b.ensure_admin("admin", "lokalpw")
_app29b = FastAPI()
_app29b.include_router(auth29b.router())
TestClient(_app29b).post("/auth/login", data={"username": "admin", "password": "lokalpw"},
                         follow_redirects=False)
assert not any(z["event"].startswith("login_l") for z in auth29b.store.recent_audit(20))
ok("F-29: without ldap_enabled no additional line")
os.remove(db29b)

# ---------- F-30: the configuration check names no remedy that it rejects itself ----------
from tinysesam import konfigpruefung as _kp  # noqa: E402
_f30, _w30 = _kp.pruefe(TinySesamConfig(db_path=":memory:", password_enabled=False,
                                        passkey_enabled=False, ldap_enabled=True,
                                        ldap_url="ldaps://ldap.example.com"))
_meldung30 = next(f for f in _f30 if "Keine einzige Anmelde-Methode" in f)
assert "ldap_enabled=True," not in _meldung30.split("LDAP allein")[0], _meldung30
assert "password_enabled=True" in _meldung30.split("LDAP allein")[1], _meldung30
assert any("ldap_enabled=True, aber password_enabled=False" in w for w in _w30), _w30
# Counter-check: the named remedy is actually accepted.
_f30b, _w30b = _kp.pruefe(TinySesamConfig(db_path=":memory:", password_enabled=True,
                                          passkey_enabled=False, ldap_enabled=True,
                                          ldap_url="ldaps://ldap.example.com"))
assert not any("Keine einzige" in f for f in _f30b) and not any("password_enabled=False" in w for w in _w30b)
ok("F-30: 'no method' no longer names ldap_enabled as a remedy; LDAP without password field warns")

print("\nLDAP-BACKEND OK ✅")
