"""TinySesam as a pure **OIDC forward-auth gateway** — deploy-and-go, without writing an app of your own.

Ways to start:
    python -m tinysesam.gateway                 # uses uvicorn (configured from env)
    uvicorn tinysesam.gateway:app               # app is built from env on access

Configuration via environment variables:
    TINYSESAM_OIDC_ISSUER          (required)  e.g. https://id.example.com
    TINYSESAM_OIDC_CLIENT_ID       (required)
    TINYSESAM_OIDC_CLIENT_SECRET   (required)
    TINYSESAM_BASE_URL             (required)  public URL of THIS gateway, e.g. https://auth.example.com
    TINYSESAM_COOKIE_DOMAIN                    e.g. .example.com  (SSO across subdomains)
    TINYSESAM_PROTECTED_HOSTS                  comma list of permitted redirect targets: app.example.com,wiki.example.com
    TINYSESAM_ALLOWED_GROUPS                   comma list. Empty = EVERY account at the provider gets
                                               through the gate — without an approval per client (below)
                                               the start therefore warns loudly (B3-9)
    TINYSESAM_OIDC_NAME                        label of the sign-in button (default "SSO"), e.g. "PocketID"
    TINYSESAM_BRAND_ICON                       favicon of all pages: path (/…) or data:image/… URI, never a foreign URL
    TINYSESAM_BRAND_BACKGROUNDS                background images (space-separated), cross-fade; covered very dark
    TINYSESAM_BRAND_BACKGROUNDS_EXTERN         1 = https addresses allowed (fetched from third parties; otherwise startup error)
    TINYSESAM_BRAND_BACKGROUND_SECONDS         display time per image (default 12)
    TINYSESAM_BRAND_BACKGROUND_CREDIT_TEXT/URL discreet note at the bottom right, e.g. "Photos: Unsplash"
    TINYSESAM_GATE_BRAND                       brand in front of the applications: sign-in page "Sign in to <brand>"
                                               with "App: <name>" below (empty = "Sign in to <name>")
    TINYSESAM_OIDC_SCOPES                      default "openid profile email". With groups at
                                               PocketID and others: "openid profile email groups" —
                                               without the scope the claim is missing, and the gate rejects
                                               everybody (the start warns)
    TINYSESAM_TRUSTED_PROXIES                  comma list; default 127.0.0.1/32,::1/128
    TINYSESAM_OIDC_CLIENTS                     JSON: several applications, each with its own
                                               client at the same provider (T-14). Example:
                                               {"app.example.com": {"client_id": "...",
                                                "client_secret": "..."}}
                                               Alternatively two variables per host, see below.
    TINYSESAM_OIDC_REVALIDATE_MINUTES          period after which the approval is re-checked
                                               at the provider (default 60, 0 = never)
    TINYSESAM_GATE                             1 = issue a gate token (ADR-9): the proxy then checks
                                               by itself, template deploy/forward-auth/Caddyfile.gate
                                               (needs Caddy with caddy-jwt). Default 0
    TINYSESAM_GATE_LINK                        1 = central gateway with code exchange (T-26): the session
                                               stays on TINYSESAM_BASE_URL, each app host gets only
                                               a connection cookie of its own. Requires TINYSESAM_GATE=1
                                               and NO TINYSESAM_COOKIE_DOMAIN. Default 0
    TINYSESAM_GATE_TTL_SEC                     lifetime of the gate token (default 300, 30–3600) —
                                               that long a revocation takes no effect at the proxy
    TINYSESAM_FORWARD_LOGIN                    direct (default: page request → provider → back) or
                                               page (first the login page with the name of the application)
    TINYSESAM_FORWARD_LOGOUT                   all (default: session and provider), app (only this
                                               application) or ask (prompt) — route /.tinysesam/logout
    TINYSESAM_FORWARD_LOGGED_OUT_SEC           mode direct: the "Signed out" page stays this long,
                                               then it returns by itself to the application and thereby
                                               to a new sign-in (default 10, 0 = leave it standing)
    TINYSESAM_FORWARD_APPS                     JSON per application: {"wiki.example.com": {"name": "Wiki",
                                               "login": "page", "logout": "ask"}} — name appears
                                               on the login and sign-out page
    TINYSESAM_DB                               default tinysesam-gateway.db
    TINYSESAM_HTTPS_MODE                       off|warn|force (default warn)
    TINYSESAM_LANG                             language of the gateway's pages: en (default) or de
    TINYSESAM_SECURITY_LOG                     file for the fail2ban logger, e.g.
                                               /var/log/tinysesam/security.log (empty = off)
    TINYSESAM_HOST / TINYSESAM_PORT            default 0.0.0.0 / 8000

The reverse proxy then calls `GET /auth/forward` per request (see deploy/forward-auth/).
Needs `pip install 'tinysesam[gateway]'` — that is `[oidc]` **plus an ASGI server**. With
`[oidc]` alone the start command below ends in `ModuleNotFoundError: uvicorn`; exactly this
line used to stand here and sent readers into the error.
"""
from __future__ import annotations

from typing import Optional
import os
import sys

from . import security
from .config import TinySesamConfig
from .manager import TinySesam


from starlette.requests import Request as _Request  # module level: FastAPI must resolve the annotation

def _split(name):
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def _host_aus_variable(rest: str, bekannte) -> str:
    """Recover the host name from `APP_B_EXAMPLE_COM`.

    A variable name carries neither dot nor hyphen, both become `_` — the
    reverse translation cannot guess whether `APP_B_EXAMPLE_COM` stands for `app.b.example.com` or
    `app-b.example.com`. So it does not guess but **matches**: every host
    from `TINYSESAM_PROTECTED_HOSTS` is normalized the same way; if exactly one fits, it is the one meant.

    Without this matching, an entry for a host that does not exist silently came into being:
    the application kept running, only its mapping never took effect, and the error showed up only as
    "why does app-b use the default client". If nothing fits, the dot stays as a guess — then
    `clients_from_env()` reports it loudly.
    """
    for host in bekannte:
        if _als_variable(host) == rest.upper():
            return host.strip().lower()
    return rest.lower().replace("_", ".")


def _als_variable(host: str) -> str:
    return str(host).strip().upper().replace(".", "_").replace("-", "_")


def clients_from_env() -> dict:
    """Read the host → client mapping from the environment (T-14).

    Two notations, because both are needed: `TINYSESAM_OIDC_CLIENTS` as JSON is the
    compact form for a compose file with many applications; the individual variables
    `TINYSESAM_OIDC_CLIENT_<HOST>_ID` and `..._SECRET` are the form in which a secret comes from
    a file or a secret store, without anyone having to assemble JSON.
    Both together are allowed; the individual variables win because they are more specific.
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
        if rest in ("ID", "SECRET"):      # that is the single client, not an application
            continue
        for endung, feld in (("_ID", "client_id"), ("_SECRET", "client_secret")):
            if rest.endswith(endung):
                roh = rest[:-len(endung)]
                host = _host_aus_variable(roh, bekannte)
                if bekannte and host not in [h.strip().lower() for h in bekannte]:
                    geraten.append((name, host))
                clients.setdefault(host, {})[feld] = wert
    if geraten:
        # Loud instead of silent: a host that is in no list never gets a request —
        # the mapping would exist and still never take effect.
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
        oidc_scopes=os.environ.get("TINYSESAM_OIDC_SCOPES", "").strip() or "openid profile email",
        oidc_name=os.environ.get("TINYSESAM_OIDC_NAME", "").strip() or "SSO",
        gate_brand=os.environ.get("TINYSESAM_GATE_BRAND", "").strip(),
        brand_icon=_favicon(),
        brand_backgrounds=_hintergruende(),
        brand_background_seconds=int(os.environ.get("TINYSESAM_BRAND_BACKGROUND_SECONDS", "12") or 12),
        brand_background_credit_text=os.environ.get("TINYSESAM_BRAND_BACKGROUND_CREDIT_TEXT", "").strip(),
        brand_background_credit_url=os.environ.get("TINYSESAM_BRAND_BACKGROUND_CREDIT_URL", "").strip(),
        db_path=os.environ.get("TINYSESAM_DB", "tinysesam-gateway.db"),
        https_mode=os.environ.get("TINYSESAM_HTTPS_MODE", "warn"),
        security_log=os.environ.get("TINYSESAM_SECURITY_LOG", ""),
        trusted_proxies=_split("TINYSESAM_TRUSTED_PROXIES") or ["127.0.0.1/32", "::1/128"],
        clients=clients_from_env(),
        revalidate_minutes=int(os.environ.get("TINYSESAM_OIDC_REVALIDATE_MINUTES", "60") or 0),
        gate_token_enabled=_schalter("TINYSESAM_GATE"),
        gate_link_enabled=_schalter("TINYSESAM_GATE_LINK"),
        lang=_sprache(),
        forward_login=os.environ.get("TINYSESAM_FORWARD_LOGIN", "").strip() or "direct",
        forward_apps=_json_objekt("TINYSESAM_FORWARD_APPS"),
        forward_logout=os.environ.get("TINYSESAM_FORWARD_LOGOUT", "").strip() or "all",
        forward_logged_out_sec=int(os.environ.get("TINYSESAM_FORWARD_LOGGED_OUT_SEC", "10") or 0),
        gate_token_ttl_sec=int(os.environ.get("TINYSESAM_GATE_TTL_SEC", "300") or 300),
    )


def _json_objekt(name: str) -> dict:
    """A JSON object from the environment, empty = {}. Broken JSON ends the start — silently
    ignored, the default would apply to every application, and nobody would see why."""
    import json
    roh = os.environ.get(name, "").strip()
    if not roh:
        return {}
    try:
        wert = json.loads(roh)
    except ValueError as e:
        raise SystemExit(f"{name} ist kein gültiges JSON: {e}")
    if not isinstance(wert, dict):
        raise SystemExit(f"{name} muss ein Objekt sein: {{\"app.example.com\": {{…}}}}")
    return wert


def _schalter(name: str) -> bool:
    """An on/off from the environment. A value that is neither ends
    the start: reading `TINYSESAM_GATE=ja` silently as "off" would mean a gate that keeps checking
    every request, and nobody would know why it does not get faster."""
    wert = os.environ.get(name, "").strip().lower()
    if wert in ("", "0", "false", "no", "off"):
        return False
    if wert in ("1", "true", "yes", "on"):
        return True
    raise SystemExit(f"{name}={wert!r}: erwartet 1 oder 0 (true/false, yes/no, on/off)")


HEALTH_PATH = "/healthz"


def _install_https_except_health(auth, app):
    """Like `auth.install_https`, but `/healthz` stays reachable over HTTP.

    With `https_mode=force` the redirect middleware would also redirect the health check —
    and that one talks to the container from the inside, where there is no TLS. A health check that
    gets a redirect back checks nothing.
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


def _favicon() -> str:
    """TINYSESAM_BRAND_ICON: favicon of all pages of the gateway. Only from the own origin — a path (`/…`) or a
    `data:image/…` URI. A foreign URL would mean every visitor reports to third parties when loading the sign-in page."""
    wert = os.environ.get("TINYSESAM_BRAND_ICON", "").strip()
    if wert and not (wert.startswith("data:image/") or (wert.startswith("/") and not wert.startswith("//"))):
        raise SystemExit("TINYSESAM_BRAND_ICON: nur ein Pfad (/…) oder eine data:image/…-URI — keine fremde Adresse")
    return wert


def _hintergruende() -> list:
    """TINYSESAM_BRAND_BACKGROUNDS: background images, separated by spaces. An https address means: every
    visitor of the sign-in page loads from that third party. That works only with explicit approval
    (TINYSESAM_BRAND_BACKGROUNDS_EXTERN=1) — otherwise a startup error, so that it never happens by accident."""
    bilder = os.environ.get("TINYSESAM_BRAND_BACKGROUNDS", "").split()
    if any(b.startswith(("http://", "https://", "//")) for b in bilder) and not _schalter("TINYSESAM_BRAND_BACKGROUNDS_EXTERN"):
        raise SystemExit("TINYSESAM_BRAND_BACKGROUNDS: fremde Adressen nur mit TINYSESAM_BRAND_BACKGROUNDS_EXTERN=1 "
                         "(jeder Besucher laedt dann bei diesem Dritten)")
    return bilder


def _sprache() -> str:
    """TINYSESAM_LANG: one of the languages TinySesam ships with — otherwise a startup error instead of
    silent English pages."""
    from .messages import MESSAGES
    wert = os.environ.get("TINYSESAM_LANG", "").strip().lower() or "en"
    if wert not in MESSAGES:
        raise SystemExit(f"TINYSESAM_LANG={wert!r}: bekannt sind {', '.join(sorted(MESSAGES))}")
    return wert


def build_app(cfg: Optional[TinySesamConfig] = None):
    """Build the FastAPI app for the gateway (cfg optional; otherwise from env)."""
    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse
    auth = TinySesam(cfg or config_from_env())
    app = FastAPI(title="TinySesam OIDC-Gateway")
    app.include_router(auth.router())
    # Browsers get the error page in the branding instead of `{"detail": "Not Found"}`; API clients
    # still get JSON (Accept decides, `install_error_pages`).
    auth.install_error_pages(app)

    @app.get("/", include_in_schema=False)
    def startseite(request: _Request):
        """Whoever opens the gateway's address does not land in the void: signed in, the overview with
        sign-out, otherwise the sign-in."""
        u = auth.session_user(request)
        if not u:
            return RedirectResponse(auth.browser_path(request, auth.cfg.login_path), 303)
        return auth.render_page("gateway_home", request=request, user_name=u["display_name"] or u["username"])

    @app.get(HEALTH_PATH, include_in_schema=False)
    def healthz():
        """Reachable without sign-in — otherwise no orchestrator could use it.

        Writes to the database once (`Store.schreibprobe()`). Very early on it only reported
        that the process is alive; after that it asked with `SELECT 1` — and that also succeeds on a
        read-only or full database (B6-4). After a rollback, on a full volume or
        wrong file permissions the service returned 500 to all users on sign-in, while
        Docker permanently kept the container as `healthy` — no restart, no alarm. A
        guard that cannot see the most likely failure is none.

        Reachable without sign-in also means: floodable. That is why the probe really writes at most every
        `Store.SCHREIBPROBE_SEK`, in between it only checks the connection — otherwise
        every call would occupy the write lock that sign-ins wait for. Like any sign-in it waits
        up to `Store.BUSY_TIMEOUT_MS` behind a foreign writer; the HEALTHCHECK in the
        Dockerfile gives it more time for that.

        Nothing is revealed all the same: on a defect only `status: "degraded"` and 503, never
        the error message (which would otherwise stand unauthenticated on the network).
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
    # Lazy `app`, so that `uvicorn tinysesam.gateway:app` works without import-time env,
    # but a plain `import tinysesam.gateway` (e.g. in tests) does NOT demand env right away.
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
    # `--help` BEFORE anything else: before, the question landed in the uvicorn import and then in
    # a server on 0.0.0.0:8000 — whoever wanted to know what the thing is called had it running.
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
        # The README named `pip install 'tinysesam[oidc]'` and this start command in one
        # breath — yet [oidc] brings no server. The bare ModuleNotFoundError made
        # that look like a defect instead of a missing line in the install command.
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
