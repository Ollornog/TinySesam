"""Login modes before the gate (T-21) and the loop on a missing app unlock (B-2).

`forward_login` / `forward_apps[host].login`: "page" sends someone not signed in to the
login page (with the name of the application), "direct" sends a page request straight to the provider.
Background requests always go to the login page — otherwise each would begin an OIDC flow of its own.
"""
import os
import re
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, ConfigError
from tinysesam import config_check
from tinysesam.oidc import DEFAULT_CLIENT


def ok(name):
    print(f"  ✓ {name}")


META = {"issuer": "https://id.example.com", "jwks_uri": "https://id.example.com/jwks",
        "token_endpoint": "https://id.example.com/token",
        "authorization_endpoint": "https://id.example.com/auth"}
PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/page"}
PAGE_HTML = {"Sec-Fetch-Mode": "navigate", "Accept": "text/html"}


def instance(cfg: TinySesamConfig):
    auth = TinySesam(cfg)
    registry = getattr(auth, "oidc_clients", None)
    if registry is not None:
        for key_name in [DEFAULT_CLIENT] + registry.names():
            registry[key_name]._meta, registry[key_name]._meta_when = dict(META), time.time()
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def gateway(**extra):
    values = dict(issuer="https://id.example.com", client_id="main", client_secret="s",
                 base_url="https://auth.example.com", db_path=os.path.join(tempfile.mkdtemp(), "g.db"),
                 trusted_redirect_hosts=["app.example.com", "wiki.example.com"],
                 allowed_groups=["people"], oidc_scopes="openid profile email groups",
                 https_mode="off", lang="de")
    values.update(extra)
    cfg = TinySesamConfig.oidc_gateway(**values)
    cfg.cookie_secure = False
    cfg.csrf_enabled = False
    return instance(cfg)


def place(r):
    return urlsplit(r.headers.get("X-TinySesam-Location", ""))


# ---------- Default in the gateway: direct ----------
auth, app = gateway(forward_apps={"wiki.example.com": {"name": "Wiki", "login": "page"}})
assert auth.cfg.forward_login == "direct"
c = TestClient(app)

r = c.get("/auth/forward", headers={**PROXY, **PAGE_HTML})
assert r.status_code == 401
assert place(r).path == "/auth/oidc/start", r.headers.get("X-TinySesam-Location")
assert parse_qs(place(r).query)["next"] == ["https://app.example.com/page"]
ok("gateway (default direct): page request → straight to /auth/oidc/start with next")

# Where does this entry point lead? To the provider, with exactly one redirect.
a = c.get(place(r).path + "?" + place(r).query, follow_redirects=False)
assert a.status_code == 303 and a.headers["location"].startswith("https://id.example.com/auth?"), a.status_code
ok("… and from there with one redirect to the provider")

for name, head in (("XHR (Sec-Fetch-Mode: cors)", {"Sec-Fetch-Mode": "cors", "Accept": "*/*"}),
                   ("Script (no-cors)", {"Sec-Fetch-Mode": "no-cors", "Accept": "*/*"}),
                   ("Tool without Sec-Fetch, Accept */*", {"Accept": "*/*"})):
    r = c.get("/auth/forward", headers={**PROXY, **head})
    assert place(r).path == "/auth/login", (name, r.headers.get("X-TinySesam-Location"))
r = c.get("/auth/forward", headers={**PROXY, "Accept": "text/html,application/xhtml+xml"})
assert place(r).path == "/auth/oidc/start"
ok("background requests → login page (no flow); without Sec-Fetch, Accept: text/html decides")

# Add a second method at runtime (`auth.cfg` is mutable): then there are paths that only
# the login page shows — direct must not skip it, even if the check at start
# knew nothing about it.
auth.cfg.password_enabled = True
r = c.get("/auth/forward", headers={**PROXY, **PAGE_HTML})
auth.cfg.password_enabled = False
assert place(r).path == "/auth/login", r.headers.get("X-TinySesam-Location")
ok("direct, but OIDC no longer the only method → login page")

# Overridden per application: wiki.example.com wants the window.
r = c.get("/auth/forward", headers={**PROXY, **PAGE_HTML, "X-Forwarded-Host": "wiki.example.com"})
assert place(r).path == "/auth/login", r.headers.get("X-TinySesam-Location")
page_html = c.get(place(r).path + "?" + place(r).query)
assert "<h1>Anmelden bei Wiki</h1>" in page_html.text, re.findall(r"<h1>.*?</h1>", page_html.text)
ok("forward_apps: wiki.example.com with login=page → login page “Anmelden bei Wiki”")

# Without a name the heading stays the service name.
page_html = c.get("/auth/login?next=" + "https%3A%2F%2Fapp.example.com%2Fx")
assert f"<h1>{auth.cfg.rp_name}</h1>" in page_html.text
ok("without name: heading as before (rp_name)")

# Library: the default stays page.
assert TinySesamConfig(db_path=":memory:").forward_login == "page"
ok("library: default stays page")

# ---------- Error at the provider: no loop ----------
r = c.get("/auth/oidc/callback?error=access_denied&state=x", follow_redirects=False)
assert r.status_code == 400 and "location" not in r.headers, r.status_code
ok("provider refusal → error page (400), no redirect back into the round")

# ---------- Configuration check ----------
def findings(**w):
    values = dict(db_path=":memory:", forward_auth_enabled=True)
    values.update(w)
    return config_check.check_config(TinySesamConfig(**values))[0]


assert any("forward_login" in b for b in findings(forward_login="invisible"))
assert any("the only login method" in b for b in findings(forward_login="direct"))   # password is on
# the German wording of the same finding with lang="de"
assert any("einzige Anmeldemethode" in b for b in findings(forward_login="direct", lang="de"))
assert not any("einzige Anmeldemethode" in b for b in findings(forward_login="direct"))
assert any("the only login method" in b
           for b in findings(forward_apps={"app.example.com": {"login": "direct"}}))
assert any("logn" in b for b in findings(forward_apps={"app.example.com": {"logn": "page"}}))
assert any("['login']" in b for b in findings(forward_apps={"app.example.com": {"login": "window"}}))
assert not [b for b in findings(forward_apps={"app.example.com": {"name": "App", "login": "page"}})
            if "forward" in b]
try:
    TinySesam(TinySesamConfig(db_path=":memory:", forward_auth_enabled=True, forward_login="direct"))
except ConfigError as e:
    assert "the only login method" in str(e)
else:
    raise AssertionError("direct next to the password login starts")
ok("configuration check: unknown mode, direct next to other methods, typo in the key")

# ---------- B-2: several clients, approval missing ----------
auth2, app2 = gateway(trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"],
                      clients={"app-a.example.com": {"client_id": "a", "client_secret": "x"},
                               "app-b.example.com": {"client_id": "b", "client_secret": "y"}})
# A session without a provider round (as after a sign-in for ANOTHER application).
uid = auth2.create_user("anna")
token = auth2.store.create_session(uid, 3600, True, "oidc")
c2 = TestClient(app2)
c2.cookies.set(auth2.session_cookie_name, token)
auth2._record_oidc_approval(token, "app-a.example.com")
PA = {**PROXY, **PAGE_HTML, "X-Forwarded-Host": "app-a.example.com"}
PB = {**PA, "X-Forwarded-Host": "app-b.example.com"}

assert c2.get("/auth/forward", headers=PA).status_code == 200
r = c2.get("/auth/forward", headers=PB)
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "app-missing"
assert place(r).path == "/auth/oidc/start", r.headers.get("X-TinySesam-Location")
assert parse_qs(place(r).query)["app"] == ["app-b.example.com"]
ok("B-2: unlock for B missing → straight to /auth/oidc/start with app=B (not the login page)")

# The login page with session but without unlock: earlier 303 back to next → loop.
r = c2.get("/auth/login?next=https%3A%2F%2Fapp-b.example.com%2Fx&app=app-b.example.com",
           follow_redirects=False)
assert r.status_code == 303
destination = urlsplit(r.headers["location"])
assert destination.path == "/auth/oidc/start" and parse_qs(destination.query)["app"] == ["app-b.example.com"], r.headers["location"]
ok("B-2: login page with session without unlock → to the provider, not back to the application")

r = c2.get("/auth/login?next=https%3A%2F%2Fapp-a.example.com%2Fx&app=app-a.example.com",
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "https://app-a.example.com/x"
r = c2.get("/auth/login?next=https%3A%2F%2Fapp-b.example.com%2Fx&app=invented.example.com",
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "https://app-b.example.com/x"
ok("B-2: with unlock → back to next; an unknown app name is not carried on")

# The button carries app= along (before it was missing, the round ran via the default client).
empty = TestClient(app2)
page_html = empty.get("/auth/login?next=https%3A%2F%2Fapp-b.example.com%2Fx&app=app-b.example.com").text
button = re.findall(r"href='([^']*oidc/start[^']*)'", page_html)
assert button and "app=app-b.example.com" in button[0], button
ok("B-2: the OIDC button of the login page carries app=")

# /auth/oidc/start without app: the host of next decides.
a = empty.get("/auth/oidc/start?next=https%3A%2F%2Fapp-b.example.com%2Fx", follow_redirects=False)
assert parse_qs(urlsplit(a.headers["location"]).query)["client_id"] == ["b"]
a = empty.get("/auth/oidc/start?next=/local", follow_redirects=False)
assert parse_qs(urlsplit(a.headers["location"]).query)["client_id"] == ["main"]
ok("B-2: /auth/oidc/start without app takes the client for the host of next (otherwise the default client)")

print("Login-Modi OK")
