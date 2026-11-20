"""HSTS (H1, ASVS 3.4.1): `config.hsts` through `install_https`, and the header in the proxy templates.

Until H1 neither the library nor any template under deploy/ set `Strict-Transport-Security`. Checked here:

  (a) `https_mode="force"`: every HTTPS response of the app carries the header — TinySesam's routes, the host
      app's own route, an error response and a streamed one; the HTTP→HTTPS redirect carries none (RFC 6797 §7.2)
  (b) `warn`/`off` and `hsts=""`: no header; an own value is passed through; a header the app sets itself wins
  (c) an unparseable value is refused at construction (a browser would ignore it without a word)
  (d) the templates: Caddy (both sites, both files), nginx (both), Traefik (both routers) set it with at least one
      year; none sets `preload`; the home-network template deliberately has none (IP address, RFC 6797 §8.1.1)
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI  # noqa: E402
from fastapi.responses import PlainTextResponse, StreamingResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


def build(**values):
    cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
                          oidc_enabled=False, csrf_enabled=False, **values)
    auth = TinySesam(cfg)
    app = FastAPI()
    app.include_router(auth.router())
    auth.install_error_pages(app)

    @app.get("/own")
    def own():
        return {"x": 1}

    @app.get("/own-hsts")
    def own_hsts():
        return PlainTextResponse("x", headers={"Strict-Transport-Security": "max-age=600"})

    @app.get("/stream")
    def stream():
        return StreamingResponse(iter([b"a", b"b"]), media_type="text/plain")

    auth.install_https(app)
    return app


HSTS = "strict-transport-security"

# ---------- (a) force: every HTTPS response ----------
app = build(https_mode="force", cookie_secure=True)
https = TestClient(app, base_url="https://auth.example.com", raise_server_exceptions=False)
for path in ("/auth/login", "/own", "/stream", "/does-not-exist", "/auth/me"):
    r = https.get(path, follow_redirects=False)
    assert r.headers.get(HSTS) == "max-age=31536000", (path, r.status_code, dict(r.headers))
r = TestClient(app, base_url="http://auth.example.com").get("/own", follow_redirects=False)
assert r.status_code in (301, 307, 308) and HSTS not in r.headers, (r.status_code, dict(r.headers))
ok("force: HSTS on TinySesam routes, own route, stream, 404 and 401 over HTTPS; none on the HTTP redirect")

# ---------- (b) when there is none, and who wins ----------
for values in ({"https_mode": "warn"}, {"https_mode": "off"}, {"https_mode": "force", "cookie_secure": True, "hsts": ""}):
    r = TestClient(build(**values), base_url="https://auth.example.com").get("/own")
    assert r.status_code == 200 and HSTS not in r.headers, (values, dict(r.headers))
custom = "max-age=63072000; includeSubDomains"
r = TestClient(build(https_mode="force", cookie_secure=True, hsts=custom), base_url="https://a.example.com").get("/own")
assert r.headers.get(HSTS) == custom, dict(r.headers)
assert https.get("/own-hsts").headers.get(HSTS) == "max-age=600", "the app's own value must win"
ok("no header with warn, off or hsts=''; an own value is passed; a value the app sets itself wins")

# ---------- (c) an unparseable value is refused ----------
for bad in ("max-age=1 includeSubDomains", "maxage=31536000", "max-age=-1", "31536000", "max-age=1; foo",
            "max-age=1\r\nX-Evil: 1", "max-age=1;\r\nincludeSubDomains", None):
    try:
        build(https_mode="force", cookie_secure=True, hsts=bad)
    except ConfigError as e:
        assert "hsts=" in str(e), e
    else:
        raise AssertionError(f"hsts={bad!r} accepted")
for good in ("max-age=0", "max-age=31536000; includeSubDomains; preload", "MAX-AGE=5;includesubdomains"):
    build(https_mode="force", cookie_secure=True, hsts=good)
ok("hsts: a value a browser would not parse (or a header injection) → ConfigError at construction")

# ---------- (d) the templates ----------
def max_age(value: str) -> int:
    m = re.search(r"max-age=(\d+)", value)
    return int(m.group(1)) if m else 0


DEPLOY = ROOT / "deploy"
for name in ("forward-auth/Caddyfile", "forward-auth/Caddyfile.gate"):
    text = (DEPLOY / name).read_text(encoding="utf-8")
    sites = re.split(r"\n(?=[a-z].*\{\n)", text)
    for host in ("auth.example.com", "app.example.com"):
        site = next(s for s in sites if s.startswith(host + " {"))
        lines = re.findall(r'^\theader Strict-Transport-Security "([^"]+)"', site, re.M)
        assert len(lines) == 1 and max_age(lines[0]) >= 31536000, (name, host, lines)
        assert "preload" not in lines[0]
for name in ("forward-auth/nginx.conf", "forward-auth/nginx-path.conf"):
    text = (DEPLOY / name).read_text(encoding="utf-8")
    lines = re.findall(r'^    add_header Strict-Transport-Security "([^"]+)" always;', text, re.M)
    assert len(lines) == 1 and max_age(lines[0]) >= 31536000 and "preload" not in lines[0], (name, lines)
    # A location with its own add_header would drop the server-level one.
    code = [z.split("#", 1)[0] for z in text.splitlines()]
    assert sum("add_header" in z for z in code) == 1, (name, [z for z in code if "add_header" in z])
assert "includeSubDomains" not in re.findall(r'add_header Strict-Transport-Security "([^"]+)"',
                                             (DEPLOY / "forward-auth/nginx-path.conf").read_text())[0], \
    "nginx-path.conf serves the parent domain — includeSubDomains is the operator's decision there"
traefik = (DEPLOY / "forward-auth/traefik.yml").read_text(encoding="utf-8")
assert re.search(r"tinysesam-hsts:\n\s+headers:\n\s+stsSeconds: (\d+)", traefik)
assert int(re.search(r"stsSeconds: (\d+)", traefik).group(1)) >= 31536000 and "stsPreload" not in traefik
routers = traefik.split("\n  routers:\n", 1)[1].split("\n  services:\n", 1)[0]
for router in ("app", "auth"):
    block = re.search(rf"^    {router}:\n((?:      .*\n|        .*\n)+)", routers + "\n", re.M).group(1)
    assert "- tinysesam-hsts" in block, (router, block)
home = (DEPLOY / "home-network/Caddyfile").read_text(encoding="utf-8")
assert "header Strict-Transport-Security" not in home and "RFC 6797, section 8.1.1" in home
ok("templates: Caddy (2 files × 2 sites), nginx (2), Traefik (both routers) ≥ 1 year, no preload; "
   "home network (IP) deliberately without, with the reason")

print("\nHSTS OK ✅")
