"""F1: SAML 2.0 SP — Login-Redirect, ACS→User/Session, Gruppen-Gate, Metadata.
ACS-Flow mit gefälschtem Client (keine echte signierte Assertion nötig); Metadata mit echtem onelogin."""
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

    def login_url(self, req, base, return_to="/"):
        return f"https://idp.example.com/sso?SAMLRequest=abc&RelayState={return_to}"

    def process(self, req, base):
        return {"nameid": self.nameid, "attrs": self.attrs} if self.valid else None

    def metadata(self, base):
        return "<md:EntityDescriptor/>"


def build(**cfgkw):
    db = tempfile.mktemp(suffix=".db")
    auth = TinySesam(TinySesamConfig(
        db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
        csrf_enabled=False, base_url="https://app.example.com",
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

print("\nSAML OK ✅")
