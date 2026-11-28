"""T-97, example Ex1: a Go application behind the TinySesam server with local accounts (deploy/ex1,
clients/go/examples/ex1).

The server is built from `deploy/ex1/tinysesam.toml` exactly as the gateway image builds it (`TINYSESAM_CONFIG`), and
does what the example promises: the sign-in page, the admin panel and the account page are served, the proxy's
`/auth/forward` guards the application's host, and the account API answers the service account's automation key — the
calls `clients/go/examples/ex1` makes (list the people, invite one with a one-time link). The Go program itself is
built and vetted by the client-go workflow (`go vet ./...`).
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
EX1 = ROOT / "deploy" / "ex1"


def ok(name):
    print(f"  ✓ {name}")


saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("TINYSESAM_")}
os.environ.update(TINYSESAM_CONFIG=str(EX1 / "tinysesam.toml"),
                  TINYSESAM_DB=os.path.join(tempfile.mkdtemp(), "ex1.db"))
try:
    from tinysesam import gateway  # noqa: E402
    app = gateway.build_app()
finally:
    for k in ("TINYSESAM_CONFIG", "TINYSESAM_DB"):
        os.environ.pop(k, None)
    os.environ.update(saved)
auth = app.state.auth
cfg = auth.cfg
assert cfg.admin_enabled and cfg.account_enabled and cfg.forward_auth_enabled and not cfg.oidc_enabled, cfg
assert "ex1" in cfg.apps and cfg.apps["ex1"]["account"] == "svc-ex1"
ok("deploy/ex1/tinysesam.toml builds the server: local accounts, panel, account page, forward auth, the ex1 app")

c = TestClient(app, base_url="https://auth.example.com")
JSON = {"Accept": "application/json"}
assert c.get("/auth/login").status_code == 200
assert c.get("/auth/admin", headers=JSON, follow_redirects=False).status_code == 401
assert c.get("/auth/account", follow_redirects=False).status_code == 303
forward = c.get("/auth/forward", headers={"X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/",
                                          "X-Forwarded-Proto": "https", **JSON}, follow_redirects=False)
assert forward.status_code == 401, forward.status_code
ok("sign-in page served; panel, account page and the application's host are closed without a session")

# The account API as the Go program calls it: the service account's automation key, the first page, an invitation.
svc = auth.create_service("svc-ex1")
key = auth.create_api_key(int(svc), name="ex1", kind="automation")["key"]
staff = int(auth.create_user("sam", password="a long probe password 4711", roles=["ex1-staff"]))
api = {"X-Api-Key": key, **JSON}
r = c.get("/auth/api/users?limit=50", headers=api)
assert r.status_code == 200 and r.json()["users"] == [], (r.status_code, r.text[:200])
r = c.post("/auth/api/users", headers={**api, "TinySesam-On-Behalf-Of": str(staff)},
           json={"username": "lena", "roles": ["ex1-member"]})
assert r.status_code in (200, 201) and r.json()["signin_url"].startswith("https://auth.example.com/"), r.text[:300]
listed = c.get("/auth/api/users?limit=50", headers=api).json()["users"]
assert [u["username"] for u in listed] == ["lena"] and listed[0]["source"] == ["local"], listed
ok("account API with the service account's key: list, invite with a one-time link, the new person listed")

# T-101: the Go program registers its manifest at start with the same key; an administrator assigns a permission; the
# proxy's forward auth sends it for the application's host, where Ex1 checks it (clients/go/examples/ex1/main_test.go).
MANIFEST = [{"name": "ex1.members.read", "label": {"en": "See the members", "de": "Mitglieder sehen"}},
            {"name": "ex1.members.invite", "label": {"en": "Invite members", "de": "Mitglieder einladen"},
             "danger": True}]
main_go = (ROOT / "clients/go/examples/ex1/main.go").read_text(encoding="utf-8")
assert all(f'"name": "{p["name"]}"' in main_go for p in MANIFEST), "the Go manifest and this test differ"
r = c.put("/auth/api/apps/ex1/permissions", headers=api, json={"permissions": MANIFEST})
assert r.status_code == 200 and sorted(r.json()["added"]) == ["ex1.members.invite", "ex1.members.read"], r.text[:300]
assert not auth.has_permission(auth.get_user(staff), "ex1.members.read", app="ex1"), "registering granted something"
auth.grant_permission("ex1-staff", "ex1.members.read", app="ex1", by="admin")
tok, _ = auth.start_session(staff, "password")
s = TestClient(app, base_url="https://auth.example.com")
s.cookies.set(auth.session_cookie_name, tok)
r = s.get("/auth/forward", headers={"X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/members",
                                    "X-Forwarded-Proto": "https"}, follow_redirects=False)
assert r.status_code == 200 and r.headers["Remote-Permissions"] == "ex1.members.read", (r.status_code, dict(r.headers))
ok("permissions: the manifest registered with the key (granting nothing), assigned to ex1-staff, sent as "
   "Remote-Permissions for app.example.com")

# T-103, surface "shell on top": on the application's host the shell gets its frame and the links by role and
# permission (the browser part is tests/test_shell_browser.py, part B).
member = int(auth.create_user("mia", password="a long probe password 4711", roles=["ex1-member"]))
app_host = {"X-Forwarded-Host": "app.example.com", "X-Forwarded-Proto": "https"}
on_app = TestClient(app, base_url="https://app.example.com")
for uid, want in ((staff, ["Home", "Members", "Staff"]), (member, ["Home"])):
    on_app.cookies.set(auth.session_cookie_name, auth.start_session(uid, "password")[0])
    frame = on_app.get("/.tinysesam/topbar.json", headers=app_host).json()["frame"]
    assert frame["layout"] == "top" and frame["name"] == "Ex1" and frame["home"] == "https://app.example.com/", frame
    assert [x["title"] for x in frame["links"]] == want, (uid, frame["links"])
r = on_app.get("/.tinysesam/shell.js", headers=app_host)
assert r.status_code == 200 and "customElements.define('ts-shell'" in r.text
main_go = (ROOT / "clients/go/examples/ex1/main.go").read_text(encoding="utf-8")
# T-144: the element names its layout itself — the same as apps.ex1.layout, so the page does not shift when the data
# arrive.
assert '<script src=\\"/.tinysesam/shell.js\\"' in main_go and '<ts-shell layout=\\"top\\" current=' in main_go
ok("shell on top: apps.ex1.layout = top, the frame of app.example.com with Members (permission) and Staff (role) for "
   "the staff, Home only for a member; shell.js served on the application's host and loaded by every Go page, the "
   "element with layout=\"top\" (T-144)")

# The pieces fit together: the compose file mounts this configuration, builds the Go program, and the application
# trusts the network Caddy talks from.
compose = (EX1 / "docker-compose.yml").read_text(encoding="utf-8")
assert "TINYSESAM_CONFIG: /etc/tinysesam.toml" in compose and "./tinysesam.toml:/etc/tinysesam.toml:ro" in compose
assert "dockerfile: examples/ex1/Dockerfile" in compose and "TS_APP_UPSTREAM: app:9000" in compose
subnet = re.search(r"subnet: (\S+)", compose).group(1)
assert f'TS_TRUSTED_PROXY: "{subnet}"' in compose and subnet in cfg.trusted_proxies, (subnet, cfg.trusted_proxies)
dockerfile = (ROOT / "clients/go/examples/ex1/Dockerfile").read_text(encoding="utf-8")
assert all("@sha256:" in line for line in dockerfile.splitlines() if line.startswith("FROM ")), "an unpinned base"
assert (ROOT / "clients/go/examples/ex1/main.go").is_file()
ok("compose: the configuration mounted, the Go image built from examples/ex1 (digest-pinned bases), one trusted subnet")

print("OK test_example_ex1")
