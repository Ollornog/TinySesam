"""T-141: `deploy/forward-auth/acceptance.sh` — the operator's check of a gate from outside — catches a proxy that
passes a client's own `Remote-Permissions` (or `Remote-Kind`) to the application.

The script runs against a small stand-in for "proxy + echo application" on loopback (no Docker): it answers what a
gate in front of an echo application answers — the sign-in redirect without a session, a share path that is open,
`/.tinysesam/*` past the gate, the sign-out of this application — and echoes the request headers the application
would receive, like traefik/whoami in deploy/quickstart. Two variants:

  good    the proxy strips every `Remote-*` header the client sent and sets TinySesam's (as the templates do)
  leaky   the proxy keeps the client's `Remote-Permissions` (a template without its strip line, T-101) — the script
          must go red, with and without a session
  leaky-kind  the same for `Remote-Kind` (the check before T-141), the counter-probe that the old checks still bite

Needs `bash` and `curl`; skips without them. tests/test_quickstart.py runs the script against the real quickstart
stack (CI job gate-caddy); tests/test_gate_caddy.py checks the templates' header lines themselves.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from voraussetzung import braucht  # noqa: E402

braucht(shutil.which("bash") and shutil.which("curl"), "bash or curl missing")

SCRIPT = os.path.join(ROOT, "deploy", "forward-auth", "acceptance.sh")
SESSION = "tinysesam_session=probe-session-value"
SHARE = "/s/abc123"


def ok(name):
    print(f"  ✓ {name}", flush=True)


class Gate(BaseHTTPRequestHandler):
    """The stand-in: `server.leak` names the client header the proxy wrongly passes on (or None)."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _echo(self, signed_in: bool):
        """What the application receives: the client's headers minus every Remote-* (the templates' duty), plus
        TinySesam's own — and, in a leaky variant, the client's header the template forgot to strip."""
        lines = [f"{k}: {v}" for k, v in self.headers.items() if not k.lower().startswith("remote-")]
        if signed_in:
            lines += ["Remote-User: probe", "Remote-Kind: user", "Remote-Auth: session"]
        leak = self.server.leak
        if leak and self.headers.get(leak) is not None:
            lines.append(f"{leak}: {self.headers[leak]}")
        self._send(200, ("\n".join(lines) + "\n").encode())

    def do_GET(self):  # noqa: N802 — the name http.server calls
        path = self.path
        signed_in = SESSION in (self.headers.get("Cookie") or "") and not self.server.signed_out
        if path == "/.tinysesam/after-logout":
            return self._send(200, b"signed out")
        if path.startswith("/.tinysesam/logout"):
            self.server.signed_out = True
            return self._send(303, headers=[("Location", "/.tinysesam/after-logout"),
                                            ("Set-Cookie", "__Host-tinysesam_gate=; Max-Age=0; Path=/; Secure")])
        if path == SHARE:
            return self._echo(signed_in=False)
        if signed_in:
            return self._echo(signed_in=True)
        return self._send(302, headers=[("Location", "https://auth.example.com/auth/login")])


def run(leak):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Gate)
    server.leak, server.signed_out = leak, False
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        env = {**os.environ, "APP": f"http://127.0.0.1:{server.server_address[1]}", "SHARE": SHARE,
               "SESSION": SESSION, "ECHO": "1", "CURL_EXTRA": ""}
        return subprocess.run(["bash", SCRIPT], capture_output=True, text=True, timeout=120, env=env)
    finally:
        server.shutdown()
        server.server_close()


good = run(None)
assert good.returncode == 0 and "passed" in good.stdout and "FAIL" not in good.stdout, good.stdout + good.stderr
perm_checks = [z for z in good.stdout.splitlines() if "Remote-Permissions" in z]
assert len(perm_checks) == 3 and all(z.startswith("  ok") for z in perm_checks), good.stdout
ok(f"a proxy that strips the client's Remote-* passes all {good.stdout.count('  ok')} checks, three of them on a "
   "forged Remote-Permissions (without sign-in, on the share path, with a session)")

leaky = run("Remote-Permissions")
failed = [z for z in leaky.stdout.splitlines() if z.startswith("  FAIL")]
assert leaky.returncode == 1 and "FAILED" in leaky.stdout, leaky.stdout
assert len(failed) == 2 and all("Remote-Permissions" in z for z in failed), leaky.stdout
assert any("share path" in z for z in failed) and any("with session" in z for z in failed), failed
ok("a proxy that passes the client's Remote-Permissions on (a template without its strip line) turns the script red — "
   "on the share path and with a session")

kind = run("Remote-Kind")
assert kind.returncode == 1 and any("Remote-Kind" in z for z in kind.stdout.splitlines() if z.startswith("  FAIL")), \
    kind.stdout
ok("counter-probe: a proxy that passes the client's Remote-Kind on still turns it red")

print("OK test_acceptance_script")
