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
    TINYSESAM_HOST / TINYSESAM_PORT            Default 0.0.0.0 / 8000

Der Reverse-Proxy ruft dann `GET /auth/forward` je Request (siehe deploy/forward-auth/).
Braucht nur `pip install 'tinysesam[oidc]'`.
"""
from __future__ import annotations
import os

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
        trusted_proxies=_split("TINYSESAM_TRUSTED_PROXIES") or ["127.0.0.1/32", "::1/128"],
    )


def build_app(cfg: TinySesamConfig = None):
    """FastAPI-App für das Gateway bauen (cfg optional; sonst aus Env)."""
    from fastapi import FastAPI
    auth = TinySesam(cfg or config_from_env())
    app = FastAPI(title="TinySesam OIDC-Gateway")
    app.include_router(auth.router())
    auth.install_https(app)   # respektiert https_mode
    app.state.auth = auth
    return app


def __getattr__(name):
    # Lazy `app`, damit `uvicorn tinysesam.gateway:app` ohne Import-Zeit-Env funktioniert,
    # ein reiner `import tinysesam.gateway` (z.B. in Tests) aber NICHT sofort Env verlangt.
    if name == "app":
        return build_app()
    raise AttributeError(name)


def main():
    import uvicorn
    host = os.environ.get("TINYSESAM_HOST", "0.0.0.0")
    port = int(os.environ.get("TINYSESAM_PORT", "8000"))
    uvicorn.run(build_app(), host=host, port=port)


if __name__ == "__main__":
    main()
