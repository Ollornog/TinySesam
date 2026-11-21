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

# ---------- the rule behind it: X-Forwarded-Host wins, a disagreeing X-Original-URL is refused ----------
# nginx (deploy/forward-auth/nginx*.conf) sets X-Original-URL AND X-Forwarded-Proto/-Host/-Uri to the same request.
NGINX_DAV = {"X-Original-URL": f"https://{DAV}/remote.php", "X-Forwarded-Proto": "https", "X-Forwarded-Host": DAV,
             "X-Forwarded-Uri": "/remote.php"}
r = c.get("/auth/forward", headers={**NGINX_DAV, "Authorization": basic})
assert r.status_code == 200 and r.headers.get("Remote-User") == "alice", r.status_code
ok("nginx with all four headers agreeing: the app password opens its own host")

# Default ports and case do not make a conflict.
r = c.get("/auth/forward", headers={**NGINX_DAV, "X-Forwarded-Host": "DAV.example.com:443", "Authorization": basic})
assert r.status_code == 200, r.status_code
ok("X-Forwarded-Host with the default port and other case agrees with X-Original-URL")

# An nginx configuration from before the templates set X-Forwarded-*: only X-Original-URL comes from nginx, the
# browser's own X-Forwarded-Host passes through. Preferring X-Forwarded-Host alone would open the same door there.
OLD_NGINX_WEB = {"X-Original-URL": f"https://{WEB}/admin"}
r = c.get("/auth/forward", headers={**OLD_NGINX_WEB, "X-Forwarded-Host": DAV, "Authorization": basic})
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "forwarded-conflict", (
    r.status_code, r.headers.get("X-TinySesam-Reason"))
assert "Remote-User" not in r.headers
ok("only X-Original-URL from the proxy, X-Forwarded-Host from the browser → refused (forwarded-conflict)")
r = c.get("/auth/forward", headers={**OLD_NGINX_WEB, "Authorization": basic})
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") != "forwarded-conflict", r.status_code
ok("only X-Original-URL (old nginx configuration, no forgery) still names the target")

for name, extra in (("scheme", {"X-Forwarded-Proto": "http"}), ("path", {"X-Forwarded-Uri": "/other"}),
                    ("port", {"X-Forwarded-Host": f"{DAV}:8443"}), ("malformed port", {"X-Forwarded-Host": f"{DAV}:x"})):
    r = c.get("/auth/forward", headers={**NGINX_DAV, **extra, "Authorization": basic})
    assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "forwarded-conflict", (name, r.status_code)
ok("a different scheme, path or port (or a malformed one) between the two is a conflict as well")

# ---------- the templates: the proxy alone names the target ----------
import pathlib  # noqa: E402
import re  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


def caddy_blocks(text: str) -> list:
    """The sub-request blocks (`rewrite /auth/forward`) of a Caddyfile, each up to its first handle_response."""
    return [part.split("handle_response", 1)[0] for part in text.split("rewrite /auth/forward")[1:]]


def caddy_strips(text: str) -> bool:
    blocks = caddy_blocks(text)
    return bool(blocks) and all(re.search(r"(?mi)^\s*header_up -X-Original-URL\s*$", b)
                                and re.search(r"(?mi)^\s*header_up -X-Original-URI\s*$", b) for b in blocks)


def nginx_consistent(text: str) -> bool:
    """Every sub-request location to /auth/forward sets X-Original-URL and X-Forwarded-Proto/-Host/-Uri itself, from
    the same request."""
    blocks = re.findall(r"location = /auth/forward[^{]*\{(.*?)\n\s*\}", text, re.S)
    want = ("X-Original-URL $scheme://$host$request_uri;", "X-Forwarded-Proto $scheme;",
            "X-Forwarded-Host $host;", "X-Forwarded-Uri $request_uri;")
    return bool(blocks) and all(all(f"proxy_set_header {w}" in b for w in want) for b in blocks)


def traefik_closed(text: str) -> bool:
    blocks = text.split("forwardAuth:")[1:]
    need = ("Authorization", "Cookie")
    out = bool(blocks)
    for b in blocks:
        b = re.split(r"(?m)^\s*authResponseHeaders:", b, maxsplit=1)[0]
        keyed = re.split(r"(?m)^\s*authRequestHeaders:", b, maxsplit=1)
        listed = re.findall(r'"([A-Za-z-]+)"', keyed[1]) if len(keyed) == 2 else []
        out = out and bool(re.search(r"(?m)^\s*trustForwardHeader:\s*false\b", b)) and all(n in listed for n in need) \
            and not any(n.lower().startswith(("x-original", "x-forwarded")) for n in listed)
    return out


CADDY = ["deploy/forward-auth/Caddyfile", "deploy/forward-auth/Caddyfile.gate", "deploy/quickstart/Caddyfile",
         "deploy/home-network/Caddyfile", "README.md", "i18n/README.de.md"]
for f in CADDY:
    text = (ROOT / f).read_text(encoding="utf-8")
    assert caddy_strips(text), f"{f}: a forward-auth block passes the browser's X-Original-URL/-URI to TinySesam"
for f in ("deploy/forward-auth/nginx.conf", "deploy/forward-auth/nginx-path.conf"):
    assert nginx_consistent((ROOT / f).read_text(encoding="utf-8")), f"{f}: a sub-request leaves a header to the client"
traefik = (ROOT / "deploy/forward-auth/traefik.yml").read_text(encoding="utf-8")
assert traefik_closed(traefik), "traefik.yml: forwardAuth trusts or copies the browser's headers"
# Every file with a forward-auth sub-request is in one of the lists above.
covered = set(CADDY) | {"deploy/forward-auth/nginx.conf", "deploy/forward-auth/nginx-path.conf",
                        "deploy/forward-auth/traefik.yml"}
for p in (ROOT / "deploy").rglob("*"):
    if p.is_file() and re.search(r"rewrite /auth/forward|auth_request |forwardAuth:", p.read_text("utf-8", "replace")):
        assert str(p.relative_to(ROOT)) in covered, f"{p.relative_to(ROOT)}: a proxy template the check does not know"
ok(f"{len(covered)} proxy templates: Caddy strips X-Original-URL/-URI, nginx sets all four, Traefik does not trust "
   "or copy the browser's forwarding headers")

# Self-probes: each check turns red on the template without its line.
caddy_text = (ROOT / CADDY[0]).read_text(encoding="utf-8")
assert not caddy_strips(caddy_text.replace("header_up -X-Original-URL\n", "", 1))
nginx_text = (ROOT / "deploy/forward-auth/nginx.conf").read_text(encoding="utf-8")
assert not nginx_consistent(nginx_text.replace("proxy_set_header X-Forwarded-Host $host;", "", 1))
assert not traefik_closed(re.sub(r"(?m)^(\s*)trustForwardHeader: false", r"\1trustForwardHeader: true", traefik,
                                 count=1))
assert not traefik_closed(traefik.replace('"Cookie"', '"X-Original-URL"', 1))
ok("self-probes: each template check fails on a template without its line")
