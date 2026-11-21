#!/usr/bin/env python3
"""End-to-end check of OAuth for services (T-60, ADR-13): the reference client against a real server behind Caddy.

Manual and optional — not part of the CI: it needs Docker (Caddy) and OpenSSL. Everything runs on 127.0.0.1 in a
throwaway directory.

    python tools/oauth-e2e/services_e2e.py [--work DIR] [--keep]

What runs:

* TinySesam in this process (uvicorn, plain HTTP on 127.0.0.1) with `oauth_service_clients`.
* Caddy in a container (`--network host`, every site bound to 127.0.0.1) with the Caddyfile GENERATED from
  `deploy/forward-auth/Caddyfile` (the same generator as `e2e.py`) — forward auth as an operator runs it.
* A small application behind Caddy that answers with the `Remote-*` headers it receives — no OAuth code in it.
* `tinysesam-client` as a separate process (`python -m tinysesam.client`), and the Python API with `httpx`.

The acceptance list (each step prints ✅/❌ and lands with evidence in <work>/report.jsonl):

1. pairing with a one-time code from the CLI → key file 0600, only the public key at the server
2. a request through Caddy → 200 with Remote-User of the service account and its roles, never admin
3. without a token, and with the token at a path outside the resource → refused by forward auth
4. the same client assertion twice over HTTPS → the second is refused (replay), the audit log names the reason
5. key rotation by the CLI → new key; a token from before and the old key keep working (overlap)
6. `httpx` with `ServiceClient.httpx_auth()` through Caddy → 200
7. the service account is locked → the token held is refused at the next request, the client gets no new one
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from e2e import CADDY_IMAGE, Report, caddyfile, free_port, make_certs, serve  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402 - module level: the annotations are resolved from here


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def app_behind(report):
    """The protected application: it only reads what the proxy passes on."""
    app = FastAPI()

    @app.get("/api/whoami")
    def whoami(request: Request):
        h = request.headers
        seen = {k: h.get(k, "") for k in ("remote-user", "remote-groups", "authorization")}
        report.log("app", **{k: v for k, v in seen.items() if k != "authorization"})
        return {"user": seen["remote-user"], "groups": seen["remote-groups"],
                "authorization_reached_app": bool(seen["authorization"])}

    @app.get("/elsewhere")
    def elsewhere():
        return {"ok": True}
    return app


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default="")
    ap.add_argument("--keep", action="store_true", help="keep the work directory")
    a = ap.parse_args()
    work = os.path.abspath(a.work or tempfile.mkdtemp(prefix="tinysesam-services-e2e-"))
    os.makedirs(f"{work}/certs", exist_ok=True)
    report = Report(f"{work}/report.jsonl")
    make_certs(f"{work}/certs")
    ca = f"{work}/certs/ca.pem"
    auth_port, app_port, ts_up, app_up = (free_port() for _ in range(4))
    base, resource = f"https://localhost:{auth_port}", f"https://127.0.0.1:{app_port}/api"
    print(f"work directory {work}", flush=True)

    from tinysesam import TinySesam, TinySesamConfig
    auth = TinySesam(TinySesamConfig(
        db_path=f"{work}/tinysesam.db", base_url=base, rp_name="TinySesam services e2e", lang="en",
        passkey_enabled=False, forward_auth_enabled=True, trusted_redirect_hosts=["127.0.0.1"],
        trusted_proxies=["127.0.0.1/32"], oauth_enabled=True, oauth_resources=[resource],
        oauth_service_clients=True, available_roles=["backup", "reader"]))
    svc = auth.create_service("backup", roles=["backup", "reader"])
    app = FastAPI()
    app.include_router(auth.router())
    servers = [serve(app, ts_up), serve(app_behind(report), app_up)]

    with open(f"{work}/Caddyfile", "w", encoding="utf-8") as fh:
        fh.write(caddyfile(auth_port, app_port, f"127.0.0.1:{ts_up}", f"127.0.0.1:{app_up}"))
    caddy = f"tinysesam-e2e-svc-{secrets.token_hex(4)}"
    subprocess.run(["sg", "docker", "-c", f"docker run -d --rm --name {caddy} --label tinysesam-e2e=1 "
                    f"--network host -v {work}/Caddyfile:/etc/caddy/Caddyfile:ro -v {work}/certs:/certs:ro "
                    f"{CADDY_IMAGE}"], check=True, capture_output=True)
    ctx = ssl.create_default_context(cafile=ca)
    env = dict(os.environ, SSL_CERT_FILE=ca, PYTHONPATH=ROOT)
    os.environ["SSL_CERT_FILE"] = ca          # the in-process client (urllib, httpx) trusts the test CA
    keyfile = f"{work}/client/backup.json"

    def cli(*args):
        r = subprocess.run([sys.executable, "-m", "tinysesam.client", "--key-file", keyfile, *args], env=env,
                           capture_output=True, text=True, timeout=60)
        report.log("cli", args=list(args[:1]), rc=r.returncode, err=r.stderr[-300:])
        return r

    def get(url, token=None):
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def audit(event):
        return [e["detail"] or "" for e in auth.store.recent_audit(500) if e["event"] == event]

    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"{base}/.well-known/oauth-authorization-server", timeout=1, context=ctx)
                break
            except Exception:
                time.sleep(0.2)

        # 1
        code = auth.create_service_pairing(svc, name="backup-job", resources=[resource])["code"]
        r = cli("pair", base, code)
        mode = stat.S_IMODE(os.stat(keyfile).st_mode) if os.path.exists(keyfile) else None
        state = read_json(keyfile) if mode else {}
        stored = auth.store.oauth_client_keys(state.get("client_id", "")) if state else []
        report.check("1 pairing by the CLI: key file 0600, only the public key at the server",
                     r.returncode == 0 and mode == 0o600 and "d" in state["key"]["jwk"]
                     and len(stored) == 1 and "d" not in stored[0]["jwk"],
                     f"rc={r.returncode} mode={oct(mode or 0)} {r.stdout.strip()}")

        # 2
        r = cli("request", "GET", f"{resource}/whoami")
        body = json.loads(r.stdout.split("\n", 1)[1]) if r.returncode == 0 else {}
        # The template passes `Authorization` on to the application (it does so for T-36 too); the application does
        # not need the token — noted in the report, not part of the check.
        report.check("2 request through Caddy: Remote-User backup with its roles",
                     r.stdout.startswith("200") and body.get("user") == "backup"
                     and set(body.get("groups", "").split(",")) == {"backup", "reader"}, r.stdout.strip()[:200])
        report.log("note", authorization_reached_app=body.get("authorization_reached_app"))
        token = cli("token").stdout.strip()
        from tinysesam import client as SC
        u, why = auth._oauth.user_for(token, f"{resource}/whoami", "127.0.0.1")
        report.check("2b the service never carries the admin flag", u is not None and u["is_admin"] == 0, why)

        # 3
        s1, _ = get(f"{resource}/whoami")
        s2, _ = get(f"https://127.0.0.1:{app_port}/elsewhere", token)
        # Outside the resource the token is no sign-in: forward auth answers as for anyone unknown (to the login).
        report.check("3 forward auth refuses: no token → 401 (Bearer), token outside its resource → not let through",
                     s1 == 401 and s2 in (302, 401), f"no token {s1}, outside {s2}")

        # 4
        sc = SC.ServiceClient(keyfile)
        assertion = sc._assertion(sc._state["key"])
        form = {"grant_type": "client_credentials", "client_assertion_type": SC.ASSERTION_TYPE,
                "client_assertion": assertion}
        first = SC.urllib_transport("POST", sc._state["token_endpoint"],
                                    {"Content-Type": "application/x-www-form-urlencoded"},
                                    urllib.parse.urlencode(form).encode())
        second = SC.urllib_transport("POST", sc._state["token_endpoint"],
                                     {"Content-Type": "application/x-www-form-urlencoded"},
                                     urllib.parse.urlencode(form).encode())
        report.check("4 the same assertion twice over HTTPS: 200, then 401 invalid_client, reason in the audit log",
                     first.status == 200 and second.status == 401 and second.json()["error"] == "invalid_client"
                     and any("replayed" in d for d in audit("oauth_client_auth_failed")),
                     f"{first.status}/{second.status}")

        # 5
        old_key = dict(sc._state["key"])
        r = cli("rotate")
        new_state = read_json(keyfile)
        s_old_token, _ = get(f"{resource}/whoami", token)
        old_again = SC.urllib_transport("POST", sc._state["token_endpoint"],
                                        {"Content-Type": "application/x-www-form-urlencoded"},
                                        urllib.parse.urlencode(dict(form, client_assertion=sc._assertion(old_key)))
                                        .encode())
        r2 = cli("request", "GET", f"{resource}/whoami")
        report.check("5 rotation by the CLI: new key; old token and old key still work (overlap); new key works",
                     r.returncode == 0 and new_state["key"]["kid"] != old_key["kid"] and s_old_token == 200
                     and old_again.status == 200 and r2.stdout.startswith("200"),
                     f"{r.stdout.strip()} old-token {s_old_token} old-key {old_again.status}")

        # 6
        import httpx
        sc2 = SC.ServiceClient(keyfile)
        with httpx.Client(verify=ssl.create_default_context(cafile=ca)) as hc:
            resp = hc.get(f"{resource}/whoami", auth=sc2.httpx_auth())
        report.check("6 httpx with ServiceClient.httpx_auth() through Caddy → 200 as backup",
                     resp.status_code == 200 and resp.json().get("user") == "backup", str(resp.status_code))

        # 7
        held = sc2.token()
        auth.set_disabled(svc, True)
        s_locked, _ = get(f"{resource}/whoami", held)
        sc2.invalidate()
        r = cli("token")
        report.check("7 account locked → the held token is refused at once, no new token",
                     s_locked == 401 and r.returncode != 0 and "invalid_client" in r.stderr,
                     f"held {s_locked}, cli rc={r.returncode} {r.stderr.strip()[:120]}")
    finally:
        subprocess.run(["sg", "docker", "-c", f"docker stop {caddy}"], capture_output=True)
        for s in servers:
            s.should_exit = True
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in report.results if not ok]
    print(f"\n{len(report.results) - len(failed)}/{len(report.results)} checks green"
          + (f" — failed: {failed}" if failed else ""), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    import urllib.error
    import urllib.parse
    raise SystemExit(main())
