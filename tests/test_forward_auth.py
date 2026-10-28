"""Phase 8: forward auth (reverse-proxy verify endpoint) + next back to the app."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from urllib.parse import urlparse
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", 
    db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
    forward_auth_enabled=True, base_url="https://auth.example.com",
    trusted_redirect_hosts=["app.example.com"]))
auth.ensure_admin("admin", "geheim123")
uid = auth.store.get_user_by_name("admin")["id"]
auth.store._exec("UPDATE users SET email=?, roles=? WHERE id=?",
                 ("admin@example.com", '["editor"]', uid))

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)

PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/geheim"}

# not signed in → 401 + login URL with next back to the app.
# This instance has NO cookie_domain, so the session cookie is host-only. The login page
# is therefore built on the requested host, not on base_url — otherwise TinySesam would set the
# cookie on auth.example.com and send the browser to app.example.com, where it does not apply:
# a silent endless loop. (Until 2026-09 base_url stood here and the test pinned down exactly the
# loop. With cookie_domain the central login still applies — see below.)
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 401
loc = r.headers.get("X-TinySesam-Location")
assert loc and loc.startswith("https://app.example.com/auth/login?next="), loc
assert urlparse(loc).netloc == "app.example.com"
ok("not signed in → 401 + X-TinySesam-Location (host-only: login on the requested host)")

# signed in (session) → 200 + Remote-* headers
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 200
assert r.headers["Remote-User"] == "admin"
assert r.headers["Remote-Email"] == "admin@example.com"
assert "editor" in r.headers["Remote-Groups"] and "admin" in r.headers["Remote-Groups"]
ok("signed in → 200 + Remote-User/Email/Groups")

# /auth/verify alias behaves the same
assert c.get("/auth/verify", headers=PROXY).status_code == 200
ok("/auth/verify alias works")

# API key satisfies forward auth (machine access)
key = auth.create_api_key(uid, name="k")["key"]
c2 = TestClient(app)
r = c2.get("/auth/forward", headers={**PROXY, "Authorization": f"Bearer {key}"})
assert r.status_code == 200 and r.headers["Remote-User"] == "admin"
ok("API key → 200 (machine access)")

# Open-redirect protection: safe_next lets the app URL through only because of trusted_redirect_hosts
assert auth.safe_next("https://app.example.com/geheim") == "https://app.example.com/geheim"
assert auth.safe_next("https://evil.example/x") == "/"
ok("safe_next: app host allowed (trusted_redirect_hosts), foreign host blocked")

# ---------- Role check in proxy mode (?roles= / X-TinySesam-Roles) ----------
auth.create_user("anna", "geheim123", roles=["redaktion"])
ca = TestClient(app)
ca.post("/auth/login", data={"username": "anna", "password": "geheim123", "next": "/"},
        follow_redirects=False)

assert ca.get("/auth/forward", headers=PROXY).status_code == 200
ok("without roles= /auth/forward stays binary (unchanged behaviour)")

assert ca.get("/auth/forward?roles=redaktion", headers=PROXY).status_code == 200
assert ca.get("/auth/forward?roles=chef,redaktion", headers=PROXY).status_code == 200
ok("?roles=a,b — one of the roles suffices")

r = ca.get("/auth/forward?roles=chef", headers=PROXY)
assert r.status_code == 403, r.status_code
assert r.headers.get("X-TinySesam-Reason") == "role"
assert "Remote-User" not in r.headers        # on 403 nothing flows to the app
ok("missing role → 403 (not 401: otherwise login loop), without Remote-* headers")

assert ca.get("/auth/forward", headers={**PROXY, "X-TinySesam-Roles": "redaktion"}).status_code == 200
assert ca.get("/auth/forward", headers={**PROXY, "X-TinySesam-Roles": "chef"}).status_code == 403
ok("header X-TinySesam-Roles acts like the query parameter")

# fail-closed: several specifications are AND-combined — a client can only tighten
assert ca.get("/auth/forward?roles=chef&roles=redaktion", headers=PROXY).status_code == 403
assert ca.get("/auth/forward?roles=redaktion",
              headers={**PROXY, "X-TinySesam-Roles": "chef"}).status_code == 403
ok("several specifications = AND (fail-closed: roles appended by oneself can only tighten)")

# Admin also satisfies the role (admin_implies_roles), anonymous users stay at 401
assert c.get("/auth/forward?roles=chef", headers=PROXY).status_code == 200
assert TestClient(app).get("/auth/forward?roles=chef", headers=PROXY).status_code == 401
ok("admin also satisfies the role; not signed in stays 401 (login, not 403)")

assert any(a["event"] == "forward_role_denied" and a["username"] == "anna"
           for a in auth.store.recent_audit(50))
ok("rejection is in the audit log (a 403 in the proxy log does not say who failed at what)")

# ---------- Login URL: host-only cookie must not point to a foreign host ----------
# Without cookie_domain the cookie applies only on the host where the login took place. If the
# login URL pointed to base_url, a silent endless loop would arise.
assert auth._forward_login_url("https://app.example.com/geheim").startswith(
    "https://app.example.com/auth/login?next=")
ok("without cookie_domain: login URL on the requested host (no redirect loop)")

assert auth._forward_login_url("https://auth.example.com/x").startswith("https://auth.example.com/auth/login")
ok("same host as base_url → unchanged")

# A forged X-Forwarded-Host cannot bend the login URL: only hosts from
# trusted_redirect_hosts come into question.
assert auth._forward_login_url("https://evil.example/x").startswith("https://auth.example.com/auth/login")
ok("foreign host outside trusted_redirect_hosts → stays at base_url")

db2 = os.path.join(tempfile.mkdtemp(), "t.db")
sso = TinySesam(TinySesamConfig(db_path=db2, csrf_enabled=False, cookie_secure=False,
                                passkey_enabled=False, forward_auth_enabled=True,
                                base_url="https://auth.example.com", cookie_domain=".example.com",
                                trusted_redirect_hosts=["app.example.com"]))
assert sso._forward_login_url("https://app.example.com/geheim").startswith(
    "https://auth.example.com/auth/login?next=")
ok("with cookie_domain: central login on base_url (real SSO across subdomains)")

# ---------- next= to the own host (single-host operation) ----------
assert auth.safe_next("https://auth.example.com/tief/drin") == "https://auth.example.com/tief/drin"
assert auth.safe_next("https://evil.example/x") == "/"
ok("safe_next: the host of the own base_url is always allowed, foreign ones not")

# ---------- Which headers go out (config.forward_headers) ----------
# The default is the Authelia set; not every downstream app wants all of them, and some
# expect other names (Grafana: X-WEBAUTH-USER, oauth2-proxy style: X-Auth-Request-*).
db3 = os.path.join(tempfile.mkdtemp(), "t.db")
eigen = TinySesam(TinySesamConfig(
    db_path=db3, csrf_enabled=False, cookie_secure=False, passkey_enabled=False,
    forward_auth_enabled=True, base_url="https://auth.example.com",
    forward_headers={"user": ["X-WEBAUTH-USER", "Remote-User"], "groups": "X-Auth-Request-Groups"}))
eigen.create_user("carla", "geheim123", roles=["redaktion"])
app3 = FastAPI()
app3.include_router(eigen.router())
c3 = TestClient(app3)
c3.post("/auth/login", data={"username": "carla", "password": "geheim123", "next": "/"},
        follow_redirects=False)
r = c3.get("/auth/forward", headers={"X-Forwarded-Proto": "https",
                                     "X-Forwarded-Host": "auth.example.com",
                                     "X-Forwarded-Uri": "/x"})
assert r.status_code == 200
assert r.headers["X-WEBAUTH-USER"] == "carla" and r.headers["Remote-User"] == "carla"
assert r.headers["X-Auth-Request-Groups"] == "redaktion"
ok("forward_headers: own names, one field may point to several headers")

assert "Remote-Email" not in r.headers and "Remote-Name" not in r.headers
ok("the list is complete, not supplementary — omitting it does not hand out the email")

# Without the field it stays with the previous set
vorgabe = auth._forward_response_headers(auth.store.get_user_by_name("admin"))
# Since 2026-09-25 `Remote-Id` (the account ID) is part of it — not silently: CHANGELOG and the
# proxy examples under deploy/ name it, and the examples set it themselves (otherwise the
# proxy would pass on one forged by the browser).
assert sorted(vorgabe) == ["Remote-Email", "Remote-Groups", "Remote-Id", "Remote-Name", "Remote-User"]
assert vorgabe["Remote-Id"] == str(auth.store.get_user_by_name("admin")["id"])
ok("default: Remote-User/-Name/-Email/-Groups and Remote-Id (the account ID)")

# A typo in the field name would silently omit the header — hence abort at startup.
# A header name with a line break would be header injection.
for kaputt in ({"mail": "X-Mail"}, {"user": "Bad Name"}, {"user": "X-U\r\nSet-Cookie: a=b"},
               {"user": ["Remote-User", ""]}):
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False,
                                  passkey_enabled=False, forward_auth_enabled=True,
                                  forward_headers=kaputt))
        raise AssertionError(f"forward_headers={kaputt} hätte abgelehnt werden müssen")
    except ValueError:
        pass
ok("unknown field and invalid header name abort at startup, not silently at runtime")

# ---------- T-14: several applications, one TinySesam ----------
# Who may enter which application is decided by the provider per OIDC client. "Signed in" is
# therefore no longer the same question as "may enter here": the approval depends on the session AND
# the application. Without this block the state from before T-14 would be back — a sign-in for
# app-a would also open app-b.
import time as _zeit                                                        # noqa: E402
from tinysesam.oidc import VORGABE_CLIENT                                    # noqa: E402

db4 = os.path.join(tempfile.mkdtemp(), "t.db")
auth4 = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="de", db_path=db4, rp_name="Test", passkey_enabled=False,
    cookie_secure=False, forward_auth_enabled=True, base_url="https://auth.example.com",
    trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"],
    oidc_enabled=True, oidc_issuer="https://id.example.com",
    oidc_client_id="haupt", oidc_client_secret="s-haupt",
    oidc_revalidate_minutes=15,
    oidc_clients={
        "app-a.example.com": {"client_id": "a", "client_secret": "s-a"},
        "app-b.example.com": {"client_id": "b", "client_secret": "s-b",
                              "group_role_map": {"b-team": "redakteur"}},
    }))
auth4.ensure_admin("admin", "geheim123")
app4 = FastAPI()
app4.include_router(auth4.router())

assert auth4.oidc_clients.namen() == ["app-a.example.com", "app-b.example.com"]
assert auth4.oidc_clients.fuer_host("app-a.example.com").client_id == "a"
assert auth4.oidc_clients.fuer_host("app-b.example.com:8443").client_id == "b"
assert auth4.oidc_clients.schluessel_fuer_host("fremd.example.com") == VORGABE_CLIENT
ok("T-14: each application has its own client, an unknown host the default client")

c14 = TestClient(app4)
c14.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"},
         follow_redirects=False)
_sitzung = c14.cookies.get("tinysesam_session")
_h = auth4.store.session_hash(_sitzung)
PROXY_A = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app-a.example.com",
           "X-Forwarded-Uri": "/geheim"}
PROXY_B = {**PROXY_A, "X-Forwarded-Host": "app-b.example.com"}

# Without approval even a valid session is not enough — the provider was never asked for this
# application. (Mutation probe: remove the check in `_forward` → 200 instead of 401.)
r = c14.get("/auth/forward", headers=PROXY_A)
assert r.status_code == 401, (r.status_code, dict(r.headers))
assert r.headers.get("X-TinySesam-Reason") == "app-fehlt", dict(r.headers)
assert "app=app-a.example.com" in r.headers.get("X-TinySesam-Location", ""), r.headers.get("X-TinySesam-Location")
ok("T-14: signed in, but without approval for this application → 401 with app= in the login URL")

# The provider has agreed for A.
auth4._record_oidc_approval(_sitzung, "app-a.example.com", rollen=["a-team"])
r = c14.get("/auth/forward", headers=PROXY_A)
assert r.status_code == 200, (r.status_code, r.headers.get("X-TinySesam-Reason"))

# …and precisely because of that not for B by a long way.
r = c14.get("/auth/forward", headers=PROXY_B)
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "app-fehlt", dict(r.headers)
assert "app=app-b.example.com" in r.headers.get("X-TinySesam-Location", "")
ok("T-14: the approval for A does not apply to B — same session, two answers")

# Revocation: the period expires, the session stays. The next call goes via the provider.
auth4.store._exec("UPDATE oidc_grant SET checked_at=? WHERE token_hash=? AND client=?",
                  (int(_zeit.time()) - 16 * 60, _h, "app-a.example.com"))
r = c14.get("/auth/forward", headers=PROXY_A)
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "app-veraltet", dict(r.headers)
assert c14.get("/auth/forward", headers=PROXY_A).status_code == 401
# The session itself is untouched — that is the difference from signing out.
assert auth4.store.get_session(_sitzung) is not None, "the session must survive the expired approval"
auth4._record_oidc_approval(_sitzung, "app-a.example.com")
assert c14.get("/auth/forward", headers=PROXY_A).status_code == 200
ok("T-14: after oidc_revalidate_minutes the approval lapses (session stays), confirmation opens it again")

# Revocation by hand: one application closed, the other open.
auth4._record_oidc_approval(_sitzung, "app-b.example.com")
assert c14.get("/auth/forward", headers=PROXY_B).status_code == 200
_weg = auth4.store.drop_oidc_grant(_h, "app-b.example.com")
assert _weg == 1
assert c14.get("/auth/forward", headers=PROXY_B).status_code == 401
assert c14.get("/auth/forward", headers=PROXY_A).status_code == 200
ok("T-14: withdrawing an approval affects exactly one application")

# The flow remembers WHICH application it runs for. The redirect URI is the same for all clients
# (the provider holds one address), so the client cannot come from the return
# address — it is in the flow record. Without it every sign-in would run via the default client
# and the approval per client would be ineffective.
_META = {"issuer": "https://id.example.com", "jwks_uri": "https://id.example.com/jwks",
         "token_endpoint": "https://id.example.com/token",
         "authorization_endpoint": "https://id.example.com/auth"}
for _schluessel in [VORGABE_CLIENT] + auth4.oidc_clients.namen():
    _k = auth4.oidc_clients[_schluessel]
    _k._meta, _k._meta_zeit = dict(_META), _zeit.time()

from urllib.parse import parse_qs as _pq                                      # noqa: E402


def _abfrage_der_umleitung(pfad):
    """The query of the provider redirect that /auth/oidc/start builds."""
    a = TestClient(app4).get(pfad, follow_redirects=False)
    assert a.status_code == 303, (pfad, a.status_code)
    return _pq(urlparse(a.headers["location"]).query)

assert _abfrage_der_umleitung("/auth/oidc/start?app=app-a.example.com")["client_id"] == ["a"]
assert _abfrage_der_umleitung("/auth/oidc/start?app=app-b.example.com")["client_id"] == ["b"]
assert _abfrage_der_umleitung("/auth/oidc/start")["client_id"] == ["haupt"]
assert _abfrage_der_umleitung("/auth/oidc/start?app=fremd.example.com")["client_id"] == ["haupt"]
_abfrage_b = _abfrage_der_umleitung("/auth/oidc/start?app=app-b.example.com")
_flow_b = auth4.store.pop_flow("oidc:" + _abfrage_b["state"][0])
assert (_flow_b or {}).get("app") == "app-b.example.com", _flow_b
ok("T-14: /auth/oidc/start chooses the client of the application and holds it in the flow record")

# And the existing-installation case: ONE client, no assignment — everything as in 0.18.0, without app= anywhere.
db5 = os.path.join(tempfile.mkdtemp(), "t.db")
auth5 = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="de", db_path=db5, rp_name="Test", passkey_enabled=False,
    cookie_secure=False, forward_auth_enabled=True, base_url="https://auth.example.com",
    trusted_redirect_hosts=["app.example.com"], oidc_enabled=True,
    oidc_issuer="https://id.example.com", oidc_client_id="haupt", oidc_client_secret="s"))
auth5.ensure_admin("admin", "geheim123")
app5 = FastAPI()
app5.include_router(auth5.router())
c15 = TestClient(app5)
c15.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"},
         follow_redirects=False)
r = c15.get("/auth/forward", headers=PROXY)
assert r.status_code == 200, (r.status_code, r.headers.get("X-TinySesam-Reason"))
assert auth5._oidc_application("https://app.example.com/x") == ""
assert "app=" not in auth5._forward_login_url("https://app.example.com/x")
assert auth5._oidc_approval_valid("egal", "egal") == (True, "")
ok("T-14: an installation with one client behaves unchanged (no app=, no approval needed)")

# The gateway preset's default is here so that a change to it gets noticed: it is the
# only place where TinySesam sets a period on its own — in the basic setup it stays 0.
_preset = TinySesamConfig.oidc_gateway(
    issuer="https://id.example.com", client_id="g", client_secret="s",
    base_url="https://auth.example.com", db_path=os.path.join(tempfile.mkdtemp(), "t.db"))
assert _preset.oidc_revalidate_minutes == 60, _preset.oidc_revalidate_minutes
assert TinySesamConfig(db_path="/dev/null").oidc_revalidate_minutes == 0
ok("T-14: oidc_gateway() rechecks hourly, the basic setup not at all")

os.remove(db)
os.remove(db2)
os.remove(db3)
os.remove(db4)
os.remove(db5)
print("\nFORWARD-AUTH OK ✅")
