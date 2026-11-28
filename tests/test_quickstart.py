"""Acceptance of the quickstart stack (deploy/quickstart) — the real compose file with the real images, over TLS.

tests/test_gate_caddy.py measures the quickstart's Caddyfile against TinySesam in Python, over plain HTTP. What only
the stack itself can show is measured here: the compose file wires gateway, Caddy and application together, Caddy gets
a certificate in the chosen TLS mode, HSTS appears exactly where a domain is, and the gateway image speaks OAuth.

Two of the four TLS modes run — the two that need no outside world:
  * `ip`        a bare IP address (192.0.2.10, RFC 5737) with Caddy's own CA, the application on :8443, no HSTS;
  * `internal`  domain names (example.com) with Caddy's own CA — the ACME-free stand-in for `acme`: the same Caddyfile
                path except the one `tls internal` line of the snippet. `acme` and `dns` need a reachable public name
                or a DNS provider account; `caddy validate` covers their syntax in the CI job.

Per mode: the gateway runs from deploy/quickstart/tinysesam.toml with the variables over it (T-133), TLS chains to the
exported root (without SNI for the IP), without sign-in a redirect to the sign-in at
TS_AUTH_HOST, a self-sent Remote-User opens nothing, with a session the application sees TinySesam's Remote-* and not
the client's forgery nor TinySesam's cookies, the OAuth resource metadata of the application come from the gateway and a
Bearer request gets the 401 with its challenge instead of a redirect — then deploy/forward-auth/acceptance.sh against
the stack.

Images: TINYSESAM_QUICKSTART_IMAGES="<gateway image> <caddy image>" — the CI job `gate-caddy` builds both from this
commit and sets it; set, it is required. Without it the suite reports "skipped". Docker must be usable by the caller
(locally: `sg docker -c '…'`). Every container carries the label `tinysesam.test=quickstart`, every port is bound to
127.0.0.1 only, and the stack (containers, network, volumes) is removed afterwards, also on failure.
"""
import http.client
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from voraussetzung import braucht  # noqa: E402

IMAGES = os.environ.get("TINYSESAM_QUICKSTART_IMAGES", "").split()
braucht(IMAGES, "TINYSESAM_QUICKSTART_IMAGES not set — gateway and caddy-gate images missing "
                "(the CI job gate-caddy builds them)")
assert len(IMAGES) == 2, f"TINYSESAM_QUICKSTART_IMAGES needs two images, got {IMAGES}"
assert shutil.which("docker") and shutil.which("bash") and shutil.which("curl"), "needs docker, bash and curl"

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "deploy/quickstart/docker-compose.yml"
ACCEPTANCE = ROOT / "deploy/forward-auth/acceptance.sh"
LABEL = "tinysesam.test=quickstart"
_tmp = tempfile.mkdtemp()


def ok(name):
    print(f"  ✓ {name}")


def run(*args, check=True, timeout=300, env=None):
    p = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, env=env)
    if check and p.returncode:
        raise AssertionError(f"{' '.join(args)} → {p.returncode}\n{p.stdout[-3000:]}\n{p.stderr[-3000:]}")
    return p


# What the gateway in the stack runs with (T-133): the file, the values only it holds, one value .env overlays.
CONFIG_SCRIPT = """
import json, os
from tinysesam.gateway import config_from_env
c = config_from_env()
print(json.dumps({"config": os.environ.get("TINYSESAM_CONFIG"), "proxies": c.trusted_proxies, "db": c.db_path,
                  "issuer": c.oidc_issuer, "admin": c.admin_enabled}))
"""


# Creates an account and a session in the gateway's database, as a sign-in at the provider would. The gateway knows
# only OIDC, and there is no provider in this test; the account is the test's own.
SESSION_SCRIPT = """
from tinysesam import TinySesam
from tinysesam.gateway import config_from_env
a = TinySesam(config_from_env())
uid = a.store.create_user("anna", display_name="Anna Example", roles=["editors"])
print(a.session_cookie_name + "=" + a._create_session(uid, 3600, True, "oidc"))
"""


class Stack:
    """One quickstart stack in one TLS mode, its ports on 127.0.0.1 only."""

    def __init__(self, mode, env):
        self.mode = mode
        self.project = f"tsqs-{mode}-{os.getpid()}"
        override = os.path.join(_tmp, f"override-{mode}.yml")
        labels = '    labels: ["%s"]\n' % LABEL
        with open(override, "w", encoding="utf-8") as f:
            f.write("services:\n"
                    f"  tinysesam:\n    image: {IMAGES[0]}\n{labels}"
                    f"  caddy:\n    image: {IMAGES[1]}\n{labels}"
                    # `!override`: the stack's own 0.0.0.0 bindings go, random ports on loopback come instead.
                    "    ports: !override\n"
                    '      - "127.0.0.1::80"\n      - "127.0.0.1::443"\n      - "127.0.0.1::8443"\n'
                    f"  app:\n{labels}")
        empty_env = os.path.join(_tmp, "empty.env")   # a developer's deploy/quickstart/.env must not leak in
        open(empty_env, "w").close()
        self.base = ["docker", "compose", "-p", self.project, "--env-file", empty_env,
                     "-f", str(COMPOSE), "-f", override]
        self.env = {**os.environ, **env}

    def compose(self, *args, check=True, timeout=300):
        return run(*self.base, *args, check=check, timeout=timeout, env=self.env)

    def up(self):
        self.compose("up", "-d", "--wait", "--wait-timeout", "180", timeout=240)
        self.ports = {}
        for inner in (80, 443, 8443):
            out = self.compose("port", "caddy", str(inner)).stdout.strip()
            self.ports[inner] = int(out.rsplit(":", 1)[1])
        for c in self.compose("ps", "-q").stdout.split():
            assert run("docker", "inspect", "-f", '{{index .Config.Labels "tinysesam.test"}}', c).stdout.strip() \
                == "quickstart", f"container {c} without the test label"

    def logs(self):
        return self.compose("logs", "--no-color", "--tail", "60", check=False).stdout

    def down(self):
        self.compose("down", "-v", "--remove-orphans", "--timeout", "5", check=False, timeout=120)


class Client:
    """HTTPS to Caddy on 127.0.0.1, while TLS (SNI, certificate check) and Host speak of the real name."""

    def __init__(self, cafile, name, port, host_header):
        # Client context with an explicit floor (CodeQL py/insecure-protocol): Caddy speaks TLS 1.3, nothing older is
        # measured here. PROTOCOL_TLS_CLIENT checks the certificate and the host name by default.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(cafile=cafile)
        self.ctx = ctx
        self.name, self.port, self.host = name, port, host_header

    def get(self, path, head=None):
        conn = http.client.HTTPSConnection(self.name, self.port, context=self.ctx, timeout=15)
        # connect to loopback, but verify and (for a domain) send SNI for the real name
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=15)
        conn.sock = self.ctx.wrap_socket(sock, server_hostname=self.name)
        conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", self.host)
        for k, v in (head or {}).items():
            conn.putheader(k, v)
        conn.endheaders()
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        conn.close()
        return r.status, r.headers, body


def whoami_headers(body):
    """traefik/whoami prints the request it received; the header lines follow the request line."""
    out = {}
    for line in body.splitlines():
        m = re.match(r"^([A-Za-z0-9-]+): (.*)$", line)
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    return out


def accept(mode, auth_host, app_host, app_port):
    app_addr = app_host if app_port == 443 else f"{app_host}:{app_port}"
    resource = f"https://{app_addr}/mcp"
    domain = mode != "ip"
    stack = Stack(mode, {
        "TS_TLS": mode, "TS_AUTH_HOST": auth_host, "TS_APP_HOST": app_host, "TS_APP_PORT": str(app_port),
        "TS_COOKIE_DOMAIN": ".example.com" if domain else "",
        "TS_OIDC_ISSUER": "https://id.example.com", "TS_OIDC_CLIENT_ID": "quickstart",
        "TS_OIDC_CLIENT_SECRET": "placeholder-only", "TS_OAUTH_RESOURCES": resource})
    try:
        stack.up()
        # Caddy issues the certificates in the background; the root exists once the first one is there.
        cert = f"/data/caddy/certificates/local/{auth_host}/{auth_host}.crt"
        for _ in range(60):
            if stack.compose("exec", "-T", "caddy", "test", "-s", cert, check=False).returncode == 0:
                break
            time.sleep(1)
        root = os.path.join(_tmp, f"root-{mode}.crt")
        with open(root, "w", encoding="utf-8") as f:
            f.write(stack.compose("exec", "-T", "caddy", "cat", "/data/caddy/pki/authorities/local/root.crt").stdout)
        auth = Client(root, auth_host, stack.ports[443], auth_host)
        app = Client(root, app_host, stack.ports[app_port], app_addr)

        st, h, _ = auth.get("/healthz")
        assert st == 200, (mode, st)
        ok(f"{mode}: TLS on {auth_host} chains to the exported root of Caddy's CA"
           + (" — without SNI, as for every IP address" if not domain else ""))

        hsts = "max-age=31536000; includeSubDomains"
        st, h, _ = app.get("/start")
        loc = h.get("Location") or ""
        assert st == 302 and loc.startswith(f"https://{auth_host}/"), (mode, st, loc)
        assert h.get("Strict-Transport-Security") == (hsts if domain else None), (mode, h.get("Strict-Transport-Security"))
        st, h, _ = app.get("/start", {"Remote-User": "admin", "Remote-Groups": "admin"})
        assert st == 302, (mode, st)
        ok(f"{mode}: without sign-in {app_addr} redirects to the sign-in at {auth_host}, a self-sent Remote-User opens "
           "nothing; HSTS " + ("set (domain)" if domain else "absent (browsers ignore it from an IP address)"))

        # T-133: the gateway in the stack reads deploy/quickstart/tinysesam.toml — the network and the database path stand
        # only there (the compose file no longer passes them), the provider from .env overlays it.
        seen = stack.compose("exec", "-T", "tinysesam", "python", "-c", CONFIG_SCRIPT).stdout.strip().splitlines()[-1]
        assert json.loads(seen) == {"config": "/etc/tinysesam.toml", "proxies": ["172.29.0.0/16"],
                                    "db": "/data/gateway.db", "issuer": "https://id.example.com", "admin": False}, seen
        ok(f"{mode}: the gateway runs from tinysesam.toml (TINYSESAM_CONFIG) with .env's variables over it (T-133)")
        session = stack.compose("exec", "-T", "tinysesam", "python", "-c", SESSION_SCRIPT).stdout.strip().splitlines()[-1]
        assert re.match(r"^(__Host-|__Secure-)?tinysesam_session=\S+$", session), session
        # With a client credential along (A-3, attack round 2026-11-21): the session signs in, and neither
        # `Authorization` nor `X-Api-Key` reaches the application.
        st, h, body = app.get("/x", {"Cookie": f"other=1; {session}",
                                     "Remote-User": "admin", "Remote-Groups": "admin",
                                     "Remote-Email": "chef@example.com", "Remote-Name": "Chef",
                                     "Authorization": "Basic not-for-the-app", "X-Api-Key": "tsk_not-for-the-app"})
        seen = whoami_headers(body)
        assert st == 200, (mode, st, body[:500])
        assert seen.get("Remote-User") == ["anna"] and seen.get("Remote-Groups") == ["editors"], (mode, seen)
        assert seen.get("Remote-Name") == ["Anna Example"], (mode, seen.get("Remote-Name"))
        # Anna has no address: TinySesam's answer carries none, the browser's goes, and no placeholder text comes (T-58).
        assert "Remote-Email" not in seen, (mode, seen.get("Remote-Email"))
        assert seen.get("Cookie") == ["other=1"], (mode, seen.get("Cookie"))
        assert not {"Authorization", "X-Api-Key"} & set(seen), (mode, seen)
        assert h.get("Strict-Transport-Security") == (hsts if domain else None), mode
        ok(f"{mode}: with a session the application sees TinySesam's Remote-* — not the client's forgery, no "
           "placeholder for the missing address, no TinySesam cookie, no Authorization/X-Api-Key")

        st, h, body = app.get("/.well-known/oauth-protected-resource/mcp")
        assert st == 200 and json.loads(body)["resource"] == resource, (mode, st, body[:300])
        st, h, _ = app.get("/mcp", {"Authorization": "Bearer not-a-token"})
        challenge = h.get("WWW-Authenticate") or ""
        assert st == 401 and challenge.startswith("Bearer") and "resource_metadata=" in challenge, (mode, st, dict(h))
        ok(f"{mode}: OAuth (T-36) — the resource metadata of {resource} come from the gateway, a Bearer request gets "
           "the 401 with its challenge instead of a redirect")

        # The operator's own check, against the stack: deploy/forward-auth/acceptance.sh, from outside.
        env = {**os.environ, "APP": f"https://{app_addr}", "SESSION": session,
               "CURL_EXTRA": f"--cacert {root} --connect-to {app_host}:{app_port}:127.0.0.1:{stack.ports[app_port]}"}
        a = run("bash", str(ACCEPTANCE), check=False, timeout=120, env=env)
        assert a.returncode == 0 and "passed" in a.stdout and "FAIL" not in a.stdout, a.stdout + a.stderr
        lines = [z for z in a.stdout.splitlines() if z.startswith("  ok")]
        assert any("HSTS" in z for z in lines) == domain, (mode, a.stdout)
        ok(f"{mode}: acceptance.sh against the stack — {len(lines)} checks passed")
    except BaseException:
        print(stack.logs(), file=sys.stderr)
        raise
    finally:
        stack.down()
    left = run("docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={stack.project}").stdout.split()
    assert not left, f"containers of {stack.project} left behind: {left}"


accept("ip", "192.0.2.10", "192.0.2.10", 8443)
accept("internal", "auth.example.com", "app.example.com", 443)
print("Quickstart stack OK")
