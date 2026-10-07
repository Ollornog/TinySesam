"""Gate-Token gemessen (T-24): dieselben Asset-Anfragen einmal über /auth/forward, einmal mit Gate-Token.

    TINYSESAM_GATE_CADDY=<caddy mit caddy-jwt> HEY=<hey> python scripts/gate_messung.py

Aufbau: TinySesam (uvicorn, ein Prozess — wie das Gateway-Abbild), Caddy mit der Vorlage
deploy/forward-auth/Caddyfile.gate, und als Anwendung eine statische Antwort von Caddy selbst. Die
Anwendung soll nichts kosten: Gemessen wird der Weg durch das Gate, nicht eine Attrappe.

Last mit `hey` (https://github.com/rakyll/hey, `go install github.com/rakyll/hey@v0.1.4`). Ein Client in
Python taugt dafür nicht: Bei 20 gleichzeitigen Anfragen misst er seine eigene Thread-Verwaltung,
und das Ergebnis kehrte sich um (erster Versuch, 2026-10-07).
"""
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CADDY = os.environ.get("TINYSESAM_GATE_CADDY", "")
HEY = os.environ.get("HEY") or shutil.which("hey") or ""
if not (CADDY and os.access(CADDY, os.X_OK) and HEY and os.access(HEY, os.X_OK)):
    sys.exit("TINYSESAM_GATE_CADDY (Caddy mit caddy-jwt) und HEY bzw. `hey` im PATH werden gebraucht.")

import uvicorn  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

ISS = "https://auth.example.com"


def freier_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main(n: int) -> None:
    tmp = tempfile.mkdtemp()
    auth = TinySesam(TinySesamConfig(
        csrf_enabled=False, lang="de", db_path=os.path.join(tmp, "t.db"), rp_name="Messung",
        passkey_enabled=False, oidc_enabled=False, cookie_secure=False, forward_auth_enabled=True,
        base_url=ISS, trusted_redirect_hosts=["app.example.com"], gate_token_enabled=True))
    auth.create_user("anna", "geheim123")
    app = FastAPI()
    app.include_router(auth.router())
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(128)
    ts = f"127.0.0.1:{s.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical"))
    threading.Thread(target=lambda: server.run(sockets=[s]), daemon=True).start()

    tc = TestClient(app)
    tc.post("/auth/login", data={"username": "anna", "password": "geheim123", "next": "/"},
            follow_redirects=False)
    sitzung = f"{auth.session_cookie_name}={tc.cookies.get(auth.session_cookie_name)}"
    r = tc.get("/auth/forward", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com",
                                         "X-Forwarded-Uri": "/"})
    gate = r.headers["X-TinySesam-Gate-Cookie"].split(";", 1)[0]

    port, app_port = freier_port(), freier_port()
    vorlage = (ROOT / "deploy/forward-auth/Caddyfile.gate").read_text(encoding="utf-8")
    text = ("{\n\tauto_https off\n\tadmin off\n}\n"
            + vorlage.replace("\napp.example.com {", f"\nhttp://app.example.com:{port} {{", 1)
                     .replace("\nauth.example.com {", f"\nhttp://auth.example.com:{port} {{", 1)
            + f"\nhttp://127.0.0.1:{app_port} {{\n\trespond \"ok\"\n}}\n")
    (pathlib.Path(tmp) / "Caddyfile").write_text(text, encoding="utf-8")
    umg = {**os.environ, "TS_GATE_PUBKEY": auth.gate_public_key(), "TS_GATE_ISSUER": ISS,
           "TS_AUTH_UPSTREAM": ts, "TS_APP_UPSTREAM": f"127.0.0.1:{app_port}",
           "XDG_DATA_HOME": tmp, "XDG_CONFIG_HOME": tmp}
    with open(os.path.join(tmp, "caddy.log"), "w") as log:
        caddy = subprocess.Popen([CADDY, "run", "--config", os.path.join(tmp, "Caddyfile"),
                                  "--adapter", "caddyfile"], stdout=log, stderr=subprocess.STDOUT, env=umg)
    time.sleep(2)

    def last(cookie: str, gleichzeitig: int):
        aus = subprocess.run([HEY, "-n", str(n), "-c", str(gleichzeitig), "-host", f"app.example.com:{port}",
                              "-H", f"Cookie: {cookie}", f"http://127.0.0.1:{port}/asset.js"],
                             capture_output=True, text=True, check=True).stdout
        codes = dict(re.findall(r"\[(\d+)\]\s+(\d+) responses", aus))
        assert codes == {"200": str(n)}, codes
        rps = float(re.search(r"Requests/sec:\s+([\d.]+)", aus).group(1))
        p50, p95 = (float(re.search(rf"{q}%+ in ([\d.]+)", aus).group(1)) * 1000 for q in (50, 95))
        return rps, p50, p95

    try:
        print(f"{n} Anfragen je Zeile, eine Sitzung, Anwendung = statische Antwort\n")
        print("| gleichzeitig | Weg | Durchsatz | Median | 95 % |")
        print("|---|---|---|---|---|")
        for gleichzeitig in (1, 20):
            auth.cfg.gate_token_enabled = False
            a = last(sitzung, gleichzeitig)
            auth.cfg.gate_token_enabled = True
            b = last(f"{sitzung}; {gate}", gleichzeitig)
            for weg, (rps, p50, p95) in (("`/auth/forward` je Anfrage", a), ("Gate-Token", b)):
                print(f"| {gleichzeitig} | {weg} | {rps:,.0f} /s | {p50:.2f} ms | {p95:.2f} ms |".replace(",", " "))
    finally:
        caddy.terminate()
        server.should_exit = True


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 3000)
