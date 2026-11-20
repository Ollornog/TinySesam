"""End-to-end: a real WebDAV client through a real Caddy with TinySesam's forward auth and an app password (T-66).

Not a CI suite and deliberately **not** `test_*.py` (`run_all.py` collects by glob): it starts throwaway containers
and needs Docker. What it proves is what only the real pieces can prove — that Caddy passes the Basic header to
`/auth/forward`, hands the Basic challenge back to the client (the `basic` branch of the recipe in the README),
forwards the body of a PUT intact behind the sub-request, and that a WebDAV client (rclone) works with an app
password and fails with the account's own password and after a revocation.

    python tests/e2e_app_passwords.py            # Docker in PATH and usable by this user
    sg docker -c 'python tests/e2e_app_passwords.py'

Everything listens on 127.0.0.1 only: TinySesam (uvicorn in this process), Caddy and `rclone serve webdav` in
containers with the host network, bound to loopback. The containers carry the label `tinysesam.e2e=app-passwords`
and a name with this process's ID; they are removed by that name at the end, also after a failure.
Exit 0 = every check green, 1 = a check red, 77 = Docker or uvicorn missing (skipped, said so).
"""
from __future__ import annotations

import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

CADDY_IMAGE = "caddy:2.11.9@sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b"
RCLONE_IMAGE = "rclone/rclone:1.76.0@sha256:7cbeec24a44f206067597c0368be4de90ae19a64d5113c7d1938bd737a81e466"
HOST = "dav.example.com"
LABEL = "tinysesam.e2e=app-passwords"
TAG = f"ts-apppw-e2e-{os.getpid()}"

try:
    import uvicorn
except ImportError:
    print("skipped: uvicorn missing")
    sys.exit(77)
if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
    print("skipped: docker not usable by this user (sg docker -c '…')")
    sys.exit(77)

from fastapi import FastAPI  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

FAILED = []


def check(name, cond, detail=""):
    print(f"  {'✓' if cond else '✗'} {name}" + ("" if cond else f" — {detail}"))
    if not cond:
        FAILED.append(name)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def docker(*args, check_rc=True, **kw):
    r = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=180, **kw)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])}…: {r.stderr.strip()}")
    return r


tmp = pathlib.Path(tempfile.mkdtemp(prefix="ts-apppw-e2e-"))
(tmp / "dav").mkdir()
(tmp / "in").mkdir()
uid = f"{os.getuid()}:{os.getgid()}"

# ---------- TinySesam ----------
auth = TinySesam(TinySesamConfig(
    lang="en", db_path=str(tmp / "t.db"), passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
    forward_auth_enabled=True, base_url="https://auth.example.com", trusted_redirect_hosts=[HOST],
    trusted_proxies=["127.0.0.1/32"], forward_apps={HOST: {"name": "Files", "app_passwords": True}}))
alice = auth.create_user("alice", "Alice-Main-Password-2026", roles=["editors"])
created = auth.create_app_password(alice, "rclone on the laptop", hosts=[HOST])
APP_PW = created["password"]
ts_app = FastAPI()
ts_app.include_router(auth.router())
TS_PORT, CADDY_PORT, DAV_PORT = free_port(), free_port(), free_port()
server = uvicorn.Server(uvicorn.Config(ts_app, host="127.0.0.1", port=TS_PORT, log_level="warning"))
threading.Thread(target=server.run, daemon=True).start()

# ---------- Caddy: the recipe from the README, with the `basic` branch ----------
(tmp / "Caddyfile").write_text(f"""{{
	auto_https off
	admin off
}}

http://{HOST}:{CADDY_PORT} {{
	bind 127.0.0.1
	route {{
		reverse_proxy 127.0.0.1:{TS_PORT} {{
			method GET
			rewrite /auth/forward
			header_up X-Forwarded-Method {{method}}
			header_up X-Forwarded-Uri {{uri}}
			@ok status 200
			handle_response @ok {{
				request_header Remote-User {{rp.header.Remote-User}}
				request_header Remote-Groups {{rp.header.Remote-Groups}}
				request_header Remote-Email {{rp.header.Remote-Email}}
				request_header Remote-Name {{rp.header.Remote-Name}}
				request_header Remote-Id {{rp.header.Remote-Id}}
			}}
			@basic {{
				status 401
				header X-Tinysesam-Reason basic
			}}
			handle_response @basic {{
				header WWW-Authenticate {{rp.header.Www-Authenticate}}
				respond 401
			}}
			@denied status 401
			handle_response @denied {{
				redir {{rp.header.X-Tinysesam-Location}} 302
			}}
			@norole status 403
			handle_response @norole {{
				respond "Access denied: missing role." 403
			}}
		}}
		reverse_proxy 127.0.0.1:{DAV_PORT} {{
			header_up -Authorization
		}}
	}}
}}
""", encoding="utf-8")

names = [f"{TAG}-dav", f"{TAG}-caddy"]
try:
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{TS_PORT}/auth/forward", timeout=1)
        except urllib.error.HTTPError:
            break
        except OSError:
            time.sleep(0.1)
    docker("run", "-d", "--name", names[0], "--label", LABEL, "--network", "host", "--user", uid,
           "-v", f"{tmp / 'dav'}:/data", RCLONE_IMAGE,
           "serve", "webdav", "/data", "--addr", f"127.0.0.1:{DAV_PORT}")
    docker("run", "-d", "--name", names[1], "--label", LABEL, "--network", "host",
           "-v", f"{tmp / 'Caddyfile'}:/etc/caddy/Caddyfile:ro", CADDY_IMAGE)
    url = f"http://{HOST}:{CADDY_PORT}"
    resolve = ["--resolve", f"{HOST}:{CADDY_PORT}:127.0.0.1"]
    for _ in range(100):
        if subprocess.run(["curl", "-s", "-o", "/dev/null", *resolve, url + "/"]).returncode == 0:
            break
        time.sleep(0.2)
    print(f"  Caddy {CADDY_IMAGE.split('@')[0]}, rclone {RCLONE_IMAGE.split('@')[0]}, on 127.0.0.1 only")

    def curl(*args):
        r = subprocess.run(["curl", "-s", "-i", *resolve, *args], capture_output=True, text=True, timeout=30)
        head = r.stdout.split("\r\n\r\n", 1)[0]
        status = int(head.split(" ", 2)[1]) if head.startswith("HTTP/") else 0
        return status, head

    def rclone(*args, password=APP_PW):
        obscured = docker("run", "--rm", "--label", LABEL, RCLONE_IMAGE, "obscure", password).stdout.strip()
        return docker("run", "--rm", "--label", LABEL, "--network", "host", "--user", uid,
                      "--add-host", f"{HOST}:127.0.0.1", "-v", f"{tmp / 'in'}:/in",
                      "-e", "RCLONE_CONFIG=/dev/null", RCLONE_IMAGE, *args,
                      "--webdav-url", url + "/", "--webdav-vendor", "other", "--webdav-user", "alice",
                      "--webdav-pass", obscured, "--retries", "1", "--low-level-retries", "1",
                      check_rc=False)

    status, head = curl("-X", "PROPFIND", "-H", "Depth: 0", url + "/")
    check("without credentials: 401 with a Basic challenge from the proxy",
          status == 401 and 'www-authenticate: basic realm="files"' in head.lower(), head)

    payload = "hello from an app password " + APP_PW[:5] + "\n"
    (tmp / "in" / "hello.txt").write_text(payload, encoding="utf-8")
    r = rclone("copyto", "/in/hello.txt", ":webdav:docs/hello.txt")
    check("rclone uploads through Caddy with the app password (PUT, MKCOL)", r.returncode == 0, r.stderr[-400:])
    stored = tmp / "dav" / "docs" / "hello.txt"
    check("the file arrived intact at the WebDAV server behind the sub-request",
          stored.exists() and stored.read_text(encoding="utf-8") == payload,
          stored.read_text(encoding="utf-8") if stored.exists() else "missing")
    r = rclone("lsf", "-R", ":webdav:")
    check("rclone lists (PROPFIND Depth 1)", r.returncode == 0 and "docs/hello.txt" in r.stdout, r.stderr[-400:])
    r = rclone("cat", ":webdav:docs/hello.txt")
    check("rclone reads it back (GET)", r.returncode == 0 and r.stdout == payload, r.stdout + r.stderr[-300:])

    status, head = curl("-u", f"alice:{APP_PW}", "-X", "PROPFIND", "-H", "Depth: 0", url + "/")
    check("curl with the app password: 207 Multi-Status", status == 207, head)
    status, head = curl("-u", "alice:Alice-Main-Password-2026", "-X", "PROPFIND", "-H", "Depth: 0", url + "/")
    check("the account's own password by Basic: 401 Basic", status == 401 and "basic realm" in head.lower(), head)
    r = rclone("lsf", ":webdav:", password="Alice-Main-Password-2026")
    check("rclone with the account's own password fails", r.returncode != 0, r.stdout)

    uses = [a for a in auth.store.recent_audit(200) if a["event"] == "app_password_use"]
    check("TinySesam audited the use (app_password_use, host)", any(f"host={HOST}" in (a["detail"] or "")
                                                                    for a in uses), uses)
    row = auth.list_app_passwords(alice)[0]
    check("last used and address recorded", bool(row["last_used"]) and row["last_ip"] == "127.0.0.1", row)

    auth.revoke_app_password(created["id"], alice)
    r = rclone("lsf", ":webdav:")
    check("after the revocation rclone fails at once", r.returncode != 0, r.stdout)
    status, head = curl("-u", f"alice:{APP_PW}", "-X", "PROPFIND", "-H", "Depth: 0", url + "/")
    check("… and curl gets 401", status == 401, head)
finally:
    for n in names:
        if FAILED:
            logs = docker("logs", "--tail", "20", n, check_rc=False)
            print(f"--- {n}\n{logs.stdout[-1500:]}{logs.stderr[-1500:]}")
        docker("rm", "-f", n, check_rc=False)
    left = docker("ps", "-a", "--filter", f"name={TAG}", "--format", "{{.Names}}", check_rc=False).stdout.split()
    check("throwaway containers removed", not left, left)
    server.should_exit = True

print(f"e2e_app_passwords: {'all green' if not FAILED else 'RED: ' + ', '.join(FAILED)}")
sys.exit(1 if FAILED else 0)
