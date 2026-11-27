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
