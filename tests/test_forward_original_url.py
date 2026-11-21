"""Attack round B (2026-11-21): forward auth trusts a client-supplied `X-Original-URL`.

`_forwarded_url()` prefers `X-Original-URL` over `X-Forwarded-Host`/`X-Forwarded-Uri` whenever it contains
`://`. Only the nginx templates set that header; Caddy (deploy/forward-auth/Caddyfile, Caddyfile.gate,
deploy/quickstart, deploy/home-network) and Traefik pass the browser's own `X-Original-URL` straight through
to `/auth/forward`. Measured with Caddy 2.11.7 and the quickstart template: an app password bound to
`dav.example.com` opened `web.example.com`, and the application received `Remote-User`.

Everything that `/auth/forward` decides per application then follows the URL the attacker names instead of
the one the proxy asks about: the host binding of app passwords (T-66), the audience of OAuth access tokens
(T-36, `resource_covers`), the approval per application (T-14) and "signed out of this application only"
(T-22). Each check below fails while the header is trusted.
"""
import base64
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig

DAV, WEB = "dav.example.com", "web.example.com"


def ok(name):
    print(f"  ✓ {name}")


auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
    oidc_enabled=False, cookie_secure=False, base_url="https://auth.example.com", forward_auth_enabled=True,
    trusted_redirect_hosts=[DAV, WEB],
    forward_apps={DAV: {"name": "Files", "app_passwords": True}, WEB: {"name": "Web"}}))
uid = auth.create_user("alice", password="a long probe password 4711")
app = FastAPI()
app.include_router(auth.router())

# What Caddy sends for a request to https://web.example.com/admin (its own X-Forwarded-* headers) — plus the
# header the browser added itself, which Caddy does not touch.
PROXY_WEB = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": WEB, "X-Forwarded-Uri": "/admin",
             "X-Forwarded-Method": "GET"}
SPOOF_DAV = {"X-Original-URL": f"https://{DAV}/"}

# ---------- app password bound to dav.example.com, used at web.example.com ----------
secret = auth.create_app_password(uid, "Phone", hosts=[DAV])["secret"]
basic = "Basic " + base64.b64encode(f"alice:{secret}".encode()).decode()
c = TestClient(app)
r = c.get("/auth/forward", headers={**PROXY_WEB, "Authorization": basic})
assert r.status_code == 401, r.status_code
ok("baseline: the app password for dav.example.com does not open web.example.com")

r = c.get("/auth/forward", headers={**PROXY_WEB, **SPOOF_DAV, "Authorization": basic})
assert r.status_code == 401 and "Remote-User" not in r.headers, (
    f"X-Original-URL from the client moved the check to {DAV}: status {r.status_code}, "
    f"Remote-User={r.headers.get('Remote-User')!r} — the app password opened {WEB}")
ok("a client-supplied X-Original-URL does not move the app-password check to another host")

# ---------- "signed out of this application only" (T-22) ----------
tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
auth.store.gate_sign_out(auth.store.session_hash(tok), WEB)
s = TestClient(app)
s.cookies.set(auth.session_cookie_name, tok)
r = s.get("/auth/forward", headers=PROXY_WEB)
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "app-signed-out", r.status_code
ok("baseline: signed out of web.example.com only → 401 there")

r = s.get("/auth/forward", headers={**PROXY_WEB, **SPOOF_DAV})
assert r.status_code == 401, (
    f"X-Original-URL from the client skipped the per-application sign-out of {WEB}: status {r.status_code}")
ok("a client-supplied X-Original-URL does not skip the per-application sign-out")
