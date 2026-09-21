"""TinySesam als reines **OIDC-Forward-Auth-Gateway** — deploy-and-go, ohne eigene App zu schreiben.

Startvarianten:
    python -m tinysesam.gateway                 # nutzt uvicorn (aus Env konfiguriert)
    uvicorn tinysesam.gateway:app               # app wird beim Zugriff aus Env gebaut

Konfiguration per Umgebungsvariablen:
    TINYSESAM_OIDC_ISSUER          (Pflicht)  z.B. https://id.example.com
    TINYSESAM_OIDC_CLIENT_ID       (Pflicht)
    TINYSESAM_OIDC_CLIENT_SECRET   (Pflicht)
    TINYSESAM_BASE_URL             (Pflicht)  öffentliche URL DIESES Gateways, z.B. https://auth.example.com
    TINYSESAM_COOKIE_DOMAIN                    z.B. .example.com  (SSO über Subdomains)
    TINYSESAM_PROTECTED_HOSTS                  Komma-Liste erlaubter Redirect-Ziele: app.example.com,wiki.example.com
    TINYSESAM_ALLOWED_GROUPS                   Komma-Liste; leer = alle
    TINYSESAM_TRUSTED_PROXIES                  Komma-Liste; Default 127.0.0.1/32,::1/128
    TINYSESAM_DB                               Default tinysesam-gateway.db
    TINYSESAM_HTTPS_MODE                       off|warn|force (Default warn)
    TINYSESAM_SECURITY_LOG                     Datei für den fail2ban-Logger, z.B.
                                               /var/log/tinysesam/security.log (leer = aus)
    TINYSESAM_HOST / TINYSESAM_PORT            Default 0.0.0.0 / 8000

Der Reverse-Proxy ruft dann `GET /auth/forward` je Request (siehe deploy/forward-auth/).
Braucht nur `pip install 'tinysesam[oidc]'`.
"""
from __future__ import annotations

from typing import Optional
import os
import sys

from . import security
from .config import TinySesamConfig
from .manager import TinySesam


def _split(name):
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def config_from_env() -> TinySesamConfig:
    def req(key):
        v = os.environ.get(key)
        if not v:
            raise SystemExit(f"Umgebungsvariable {key} fehlt (siehe python -m tinysesam.gateway --help / Modul-Docstring)")
        return v
    return TinySesamConfig.oidc_gateway(
        issuer=req("TINYSESAM_OIDC_ISSUER"),
        client_id=req("TINYSESAM_OIDC_CLIENT_ID"),
        client_secret=req("TINYSESAM_OIDC_CLIENT_SECRET"),
        base_url=req("TINYSESAM_BASE_URL"),
        cookie_domain=os.environ.get("TINYSESAM_COOKIE_DOMAIN", ""),
        trusted_redirect_hosts=_split("TINYSESAM_PROTECTED_HOSTS"),
        allowed_groups=_split("TINYSESAM_ALLOWED_GROUPS"),
        db_path=os.environ.get("TINYSESAM_DB", "tinysesam-gateway.db"),
        https_mode=os.environ.get("TINYSESAM_HTTPS_MODE", "warn"),
        security_log=os.environ.get("TINYSESAM_SECURITY_LOG", ""),
        trusted_proxies=_split("TINYSESAM_TRUSTED_PROXIES") or ["127.0.0.1/32", "::1/128"],
    )


HEALTH_PATH = "/healthz"


def _install_https_except_health(auth, app):
    """Wie `auth.install_https`, aber `/healthz` bleibt über HTTP erreichbar.

    Bei `https_mode=force` würde die Redirect-Middleware auch den Health-Check umleiten —
    und der spricht den Container von innen an, wo es kein TLS gibt. Ein Health-Check, der
    einen Redirect zurückbekommt, prüft nichts.
    """
    if auth.cfg.https_mode != "force":
        return auth.install_https(app)

    from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

    class _ExceptHealth(HTTPSRedirectMiddleware):
        async def __call__(self, scope, receive, send):
            if scope.get("type") == "http" and scope.get("path") == HEALTH_PATH:
                return await self.app(scope, receive, send)
            await super().__call__(scope, receive, send)

    app.add_middleware(_ExceptHealth)
    return "force"


def build_app(cfg: Optional[TinySesamConfig] = None):
    """FastAPI-App für das Gateway bauen (cfg optional; sonst aus Env)."""
    from fastapi import FastAPI
    auth = TinySesam(cfg or config_from_env())
    app = FastAPI(title="TinySesam OIDC-Gateway")
    app.include_router(auth.router())

    @app.get(HEALTH_PATH, include_in_schema=False)
    def healthz():
        """Ohne Anmeldung erreichbar — sonst könnte kein Orchestrator ihn benutzen.

        Fragt die Datenbank mit einem `SELECT 1`. Vorher meldete er nur, dass der Prozess lebt:
        Nach einem Rollback, bei vollem Volume oder falschen Dateirechten lieferte der Dienst
        allen angemeldeten Nutzern 500, während Docker den Container dauerhaft als `healthy`
        führte — kein Neustart, kein Alarm. Ein Wächter, der den wahrscheinlichsten Ausfall
        nicht sehen kann, ist keiner.

        Verraten wird trotzdem nichts: bei einem Defekt nur `status: "degraded"` und 503, nie
        die Fehlermeldung (die stünde sonst unauthentifiziert im Netz).
        """
        from fastapi.responses import JSONResponse

        from . import current_version
        try:
            auth.store._one("SELECT 1 AS eins")
        except Exception as e:
            security.seclog.error("Healthcheck: Datenbank nicht erreichbar (%s)", type(e).__name__)
            return JSONResponse({"status": "degraded", "version": current_version()},
                                status_code=503)
        return {"status": "ok", "version": current_version()}

    _install_https_except_health(auth, app)
    app.state.auth = auth
    return app


def __getattr__(name):
    # Lazy `app`, damit `uvicorn tinysesam.gateway:app` ohne Import-Zeit-Env funktioniert,
    # ein reiner `import tinysesam.gateway` (z.B. in Tests) aber NICHT sofort Env verlangt.
    if name == "app":
        return build_app()
    raise AttributeError(name)


HILFE = """tinysesam.gateway — TinySesam als OIDC-Forward-Auth-Gateway

  python -m tinysesam.gateway          startet den Dienst
  uvicorn tinysesam.gateway:app        dasselbe über einen eigenen Server-Aufruf

Installation:  pip install 'tinysesam[gateway]'   (nicht [oidc] — das ist die Bibliothek
                                                   ohne Server)

Konfiguriert wird über Umgebungsvariablen:
  TINYSESAM_OIDC_ISSUER          Adresse des Providers            (Pflicht)
  TINYSESAM_OIDC_CLIENT_ID       Client-ID                        (Pflicht)
  TINYSESAM_OIDC_CLIENT_SECRET   Client-Secret                    (Pflicht)
  TINYSESAM_BASE_URL             eigene öffentliche Adresse       (Pflicht)
  TINYSESAM_PROTECTED_HOSTS      Hosts hinter dem Proxy, kommagetrennt
  TINYSESAM_COOKIE_DOMAIN        z.B. .example.com — für mehrere Hosts
  TINYSESAM_TRUSTED_PROXIES      Netz des Proxys, z.B. 172.28.0.0/16
  TINYSESAM_DB                   Pfad der Datenbank
  TINYSESAM_HOST / _PORT         Bindeadresse (Vorgabe 0.0.0.0:8000)

Beispielaufbau mit Caddy: deploy/forward-auth/
"""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # `--help` VOR allem anderen: Vorher landete die Frage im uvicorn-Import und danach in
    # einem Server auf 0.0.0.0:8000 — wer wissen wollte, wie das Ding heisst, hatte es laufen.
    if argv and argv[0] in ("--help", "-h", "help"):
        print(HILFE)
        return 0
    if argv:
        print(f"Unbekanntes Argument: {argv[0]}\n", file=sys.stderr)
        print(HILFE, file=sys.stderr)
        return 2
    try:
        import uvicorn
    except ModuleNotFoundError:
        # Die README nannte `pip install 'tinysesam[oidc]'` und diesen Startbefehl in einem
        # Atemzug — dabei bringt [oidc] keinen Server mit. Der nackte ModuleNotFoundError liess
        # das wie einen Defekt aussehen statt wie eine fehlende Zeile im Install-Befehl.
        print("Zum Starten fehlt ein ASGI-Server.\n"
              "  pip install 'tinysesam[gateway]'\n"
              "Oder einen eigenen mitbringen:  uvicorn tinysesam.gateway:app --host 0.0.0.0 --port 8000",
              file=sys.stderr)
        return 1
    host = os.environ.get("TINYSESAM_HOST", "0.0.0.0")
    port = int(os.environ.get("TINYSESAM_PORT", "8000"))
    uvicorn.run(build_app(), host=host, port=port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
