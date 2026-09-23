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
    TINYSESAM_OIDC_CLIENTS                     JSON: mehrere Anwendungen, je eine mit eigenem
                                               Client beim selben Provider (T-14). Beispiel:
                                               {"app.example.com": {"client_id": "...",
                                                "client_secret": "..."}}
                                               Alternativ je Host zwei Variablen, siehe unten.
    TINYSESAM_OIDC_REVALIDATE_MINUTES          Frist, nach der die Freigabe beim Provider
                                               nachgeprüft wird (Default 60, 0 = nie)
    TINYSESAM_DB                               Default tinysesam-gateway.db
    TINYSESAM_HTTPS_MODE                       off|warn|force (Default warn)
    TINYSESAM_SECURITY_LOG                     Datei für den fail2ban-Logger, z.B.
                                               /var/log/tinysesam/security.log (leer = aus)
    TINYSESAM_HOST / TINYSESAM_PORT            Default 0.0.0.0 / 8000

Der Reverse-Proxy ruft dann `GET /auth/forward` je Request (siehe deploy/forward-auth/).
Braucht `pip install 'tinysesam[gateway]'` — das ist `[oidc]` **plus einen ASGI-Server**. Mit
`[oidc]` allein endet der Startbefehl unten in `ModuleNotFoundError: uvicorn`; genau diese
Zeile stand hier früher und schickte die Leserschaft in den Fehler.
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


def _host_aus_variable(rest: str, bekannte) -> str:
    """Aus `APP_B_EXAMPLE_COM` den Hostnamen zurückgewinnen.

    Ein Variablenname trägt weder Punkt noch Bindestrich, beide werden zu `_` — die
    Rückübersetzung kann also nicht raten, ob `APP_B_EXAMPLE_COM` für `app.b.example.com` oder
    `app-b.example.com` steht. Deshalb wird nicht geraten, sondern **abgeglichen**: Jeder Host
    aus `TINYSESAM_PROTECTED_HOSTS` wird genauso normalisiert; passt genau einer, ist er gemeint.

    Ohne diesen Abgleich entstand stillschweigend ein Eintrag für einen Host, den es nicht gibt:
    Die Anwendung lief weiter, nur ihre Zuordnung griff nie, und der Fehler zeigte sich erst als
    „warum benutzt app-b den Vorgabe-Client". Passt nichts, bleibt der Punkt als Vermutung — dann
    meldet `clients_from_env()` das laut.
    """
    for host in bekannte:
        if _als_variable(host) == rest.upper():
            return host.strip().lower()
    return rest.lower().replace("_", ".")


def _als_variable(host: str) -> str:
    return str(host).strip().upper().replace(".", "_").replace("-", "_")


def clients_from_env() -> dict:
    """Die Zuordnung Host → Client aus der Umgebung lesen (T-14).

    Zwei Schreibweisen, weil beide gebraucht werden: `TINYSESAM_OIDC_CLIENTS` als JSON ist die
    knappe Form für eine compose-Datei mit vielen Anwendungen; die Einzelvariablen
    `TINYSESAM_OIDC_CLIENT_<HOST>_ID` und `..._SECRET` sind die Form, in der ein Geheimnis aus
    einer Datei oder einem Secret-Store kommt, ohne dass jemand JSON zusammensetzen muss.
    Beides zusammen ist erlaubt; die Einzelvariablen gewinnen, weil sie spezifischer sind.
    """
    clients: dict = {}
    roh = os.environ.get("TINYSESAM_OIDC_CLIENTS", "").strip()
    if roh:
        import json
        try:
            geladen = json.loads(roh)
        except ValueError as e:
            raise SystemExit(f"TINYSESAM_OIDC_CLIENTS ist kein gültiges JSON: {e}")
        if not isinstance(geladen, dict):
            raise SystemExit("TINYSESAM_OIDC_CLIENTS muss ein Objekt sein: "
                             '{"app.example.com": {"client_id": "...", "client_secret": "..."}}')
        for host, eintrag in geladen.items():
            if not isinstance(eintrag, dict):
                raise SystemExit(f"TINYSESAM_OIDC_CLIENTS[{host!r}] muss ein Objekt sein "
                                 "(client_id, client_secret, optional scopes/allowed_groups).")
            clients[str(host).strip().lower()] = dict(eintrag)
    bekannte = _split("TINYSESAM_PROTECTED_HOSTS")
    geraten = []
    for name, wert in sorted(os.environ.items()):
        if not name.startswith("TINYSESAM_OIDC_CLIENT_"):
            continue
        rest = name[len("TINYSESAM_OIDC_CLIENT_"):]
        if rest in ("ID", "SECRET"):      # das ist der Einzel-Client, nicht eine Anwendung
            continue
        for endung, feld in (("_ID", "client_id"), ("_SECRET", "client_secret")):
            if rest.endswith(endung):
                roh = rest[:-len(endung)]
                host = _host_aus_variable(roh, bekannte)
                if bekannte and host not in [h.strip().lower() for h in bekannte]:
                    geraten.append((name, host))
                clients.setdefault(host, {})[feld] = wert
    if geraten:
        # Laut statt still: Ein Host, der in keiner Liste steht, bekommt nie eine Anfrage —
        # die Zuordnung wäre da und wirkte trotzdem nie.
        security.seclog.warning(
            "Diese Client-Variablen nennen Hosts, die nicht in TINYSESAM_PROTECTED_HOSTS stehen: "
            "%s. Ein Unterstrich im Variablennamen kann ein Punkt ODER ein Bindestrich sein — "
            "steht der Host in PROTECTED_HOSTS, wird er erkannt, sonst wird der Punkt vermutet. "
            "Sicherer ist TINYSESAM_OIDC_CLIENTS als JSON.",
            ", ".join(f"{n} → {h}" for n, h in geraten))
    return clients


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
        clients=clients_from_env(),
        revalidate_minutes=int(os.environ.get("TINYSESAM_OIDC_REVALIDATE_MINUTES", "60") or 0),
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
            return await super().__call__(scope, receive, send)

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

        Schreibt einmal in die Datenbank (`Store.schreibprobe()`). Ganz früher meldete er nur,
        dass der Prozess lebt; danach fragte er mit `SELECT 1` — und das gelingt auch auf einer
        nur lesbaren oder vollen Datenbank (B6-4). Nach einem Rollback, bei vollem Volume oder
        falschen Dateirechten lieferte der Dienst allen Nutzern beim Anmelden 500, während
        Docker den Container dauerhaft als `healthy` führte — kein Neustart, kein Alarm. Ein
        Wächter, der den wahrscheinlichsten Ausfall nicht sehen kann, ist keiner.

        Verraten wird trotzdem nichts: bei einem Defekt nur `status: "degraded"` und 503, nie
        die Fehlermeldung (die stünde sonst unauthentifiziert im Netz).
        """
        from fastapi.responses import JSONResponse

        from . import current_version
        try:
            auth.store.schreibprobe()
        except Exception as e:
            security.seclog.error("Healthcheck: Datenbank nicht beschreibbar (%s: %s)",
                                  type(e).__name__, e)
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
  TINYSESAM_OIDC_CLIENTS         mehrere Anwendungen als JSON (Host → Client)
  TINYSESAM_OIDC_CLIENT_<HOST>_ID / _SECRET   dasselbe je Host einzeln
  TINYSESAM_OIDC_REVALIDATE_MINUTES           Frist der Nachprüfung (Default 60)
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
