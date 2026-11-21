"""TinySesam as a pure **OIDC forward-auth gateway** — deploy-and-go, without writing an app of your own.

Ways to start:
    python -m tinysesam.gateway                 # uses uvicorn (configured from env)
    uvicorn tinysesam.gateway:app --ws none --no-proxy-headers   # app is built from env on access

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
    TINYSESAM_OAUTH_RESOURCES                  comma list of protected resources (absolute https URLs, e.g.
                                               https://app.example.com/mcp): switches on the OAuth 2.1
                                               authorization server for MCP clients (T-36, README "OAuth for
                                               MCP clients"). Empty = off (default)
    TINYSESAM_OAUTH_SERVICE_CLIENTS            1 = services with client_credentials and private_key_jwt (T-60,
                                               README "A service calls a protected app"); needs
                                               TINYSESAM_OAUTH_RESOURCES. Pair one with
                                               `python -m tinysesam.gateway pair <account>`. Default 0
    TINYSESAM_TOPBAR_LINKS                     JSON list of [title, target] pairs for the top bar of the
                                               gateway's pages: [["Wiki", "/wiki"]] — a path on the gateway's
                                               origin or an https address on a protected host
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


def _host_from_variable(rest: str, known) -> str:
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
    for host in known:
        if _as_variable(host) == rest.upper():
            return host.strip().lower()
    return rest.lower().replace("_", ".")


def _as_variable(host: str) -> str:
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
    raw = os.environ.get("TINYSESAM_OIDC_CLIENTS", "").strip()
    if raw:
        import json
        try:
            loaded = json.loads(raw)
        except ValueError as e:
            raise SystemExit(f"TINYSESAM_OIDC_CLIENTS is not valid JSON: {e}")
        if not isinstance(loaded, dict):
            raise SystemExit("TINYSESAM_OIDC_CLIENTS must be an object: "
                             '{"app.example.com": {"client_id": "...", "client_secret": "..."}}')
        for host, entry in loaded.items():
            if not isinstance(entry, dict):
                raise SystemExit(f"TINYSESAM_OIDC_CLIENTS[{host!r}] must be an object "
                                 "(client_id, client_secret, optional scopes/allowed_groups).")
            clients[str(host).strip().lower()] = dict(entry)
    known = _split("TINYSESAM_PROTECTED_HOSTS")
    guessed = []
    for name, value in sorted(os.environ.items()):
        if not name.startswith("TINYSESAM_OIDC_CLIENT_"):
            continue
        rest = name[len("TINYSESAM_OIDC_CLIENT_"):]
        if rest in ("ID", "SECRET"):      # that is the single client, not an application
            continue
        for suffix, slot in (("_ID", "client_id"), ("_SECRET", "client_secret")):
            if rest.endswith(suffix):
                raw = rest[:-len(suffix)]
                host = _host_from_variable(raw, known)
                if known and host not in [h.strip().lower() for h in known]:
                    guessed.append((name, host))
                clients.setdefault(host, {})[slot] = value
    if guessed:
        # Loud instead of silent: a host that is in no list never gets a request —
        # the mapping would exist and still never take effect.
        security.seclog.warning(
            "These client variables name hosts that are not in TINYSESAM_PROTECTED_HOSTS: "
            "%s. An underscore in the variable name can be a dot OR a hyphen — "
            "if the host is in PROTECTED_HOSTS it is recognised, otherwise a dot is assumed. "
            "TINYSESAM_OIDC_CLIENTS as JSON is safer.",
            ", ".join(f"{n} → {h}" for n, h in guessed))
    return clients


def config_from_env() -> TinySesamConfig:
    def req(key):
        v = os.environ.get(key)
        if not v:
            raise SystemExit(f"Environment variable {key} is missing (see python -m tinysesam.gateway --help / module docstring)")
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
        brand_backgrounds=_background(),
        brand_background_seconds=int(os.environ.get("TINYSESAM_BRAND_BACKGROUND_SECONDS", "12") or 12),
        brand_background_credit_text=os.environ.get("TINYSESAM_BRAND_BACKGROUND_CREDIT_TEXT", "").strip(),
        brand_background_credit_url=os.environ.get("TINYSESAM_BRAND_BACKGROUND_CREDIT_URL", "").strip(),
        db_path=os.environ.get("TINYSESAM_DB", "tinysesam-gateway.db"),
        https_mode=os.environ.get("TINYSESAM_HTTPS_MODE", "warn"),
        security_log=os.environ.get("TINYSESAM_SECURITY_LOG", ""),
        trusted_proxies=_split("TINYSESAM_TRUSTED_PROXIES") or ["127.0.0.1/32", "::1/128"],
        clients=clients_from_env(),
        revalidate_minutes=int(os.environ.get("TINYSESAM_OIDC_REVALIDATE_MINUTES", "60") or 0),
        gate_token_enabled=_switch("TINYSESAM_GATE"),
        gate_link_enabled=_switch("TINYSESAM_GATE_LINK"),
        lang=_language(),
        forward_login=os.environ.get("TINYSESAM_FORWARD_LOGIN", "").strip() or "direct",
        forward_apps=_json_object("TINYSESAM_FORWARD_APPS"),
        forward_logout=os.environ.get("TINYSESAM_FORWARD_LOGOUT", "").strip() or "all",
        forward_logged_out_sec=int(os.environ.get("TINYSESAM_FORWARD_LOGGED_OUT_SEC", "10") or 0),
        gate_token_ttl_sec=int(os.environ.get("TINYSESAM_GATE_TTL_SEC", "300") or 300),
        oauth_enabled=bool(_split("TINYSESAM_OAUTH_RESOURCES")),
        oauth_resources=_split("TINYSESAM_OAUTH_RESOURCES"),
        oauth_service_clients=_switch("TINYSESAM_OAUTH_SERVICE_CLIENTS"),
        topbar_links=_topbar_links(),
    )


def _topbar_links() -> list:
    """TINYSESAM_TOPBAR_LINKS: links in the top bar of the gateway's pages, a JSON list of [title, target] pairs —
    `[["Wiki", "/wiki"], ["Files", "https://files.example.com/"]]` —, each optionally with a visibility as third
    element (T-76): `["Admin", "/admin", {"admin": true}]`, `["Team", "/team", {"role": "teamadmin"}]`. What a target
    and a visibility may be is checked by `config_check` (own origin, `base_url` or a protected host; exactly one of
    admin/role); the shape is checked here, so a broken value ends the start instead of leaving the bar silently
    empty."""
    import json
    raw = os.environ.get("TINYSESAM_TOPBAR_LINKS", "").strip()
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except ValueError as e:
        raise SystemExit(f"TINYSESAM_TOPBAR_LINKS is not valid JSON: {e}")
    if not isinstance(value, list) or not all(isinstance(z, list) and len(z) in (2, 3)
                                              and all(isinstance(x, str) for x in z[:2])
                                              and (len(z) == 2 or isinstance(z[2], dict)) for z in value):
        raise SystemExit('TINYSESAM_TOPBAR_LINKS must be a list of [title, target] pairs, each optionally with a '
                         'visibility: [["Wiki", "/wiki"], ["Admin", "/admin", {"admin": true}]]')
    return [tuple(z) for z in value]


def _json_object(name: str) -> dict:
    """A JSON object from the environment, empty = {}. Broken JSON ends the start — silently
    ignored, the default would apply to every application, and nobody would see why."""
    import json
    raw = os.environ.get(name, "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except ValueError as e:
        raise SystemExit(f"{name} is not valid JSON: {e}")
    if not isinstance(value, dict):
        raise SystemExit(f"{name} must be an object: {{\"app.example.com\": {{…}}}}")
    return value


def _switch(name: str) -> bool:
    """An on/off from the environment. A value that is neither ends
    the start: reading `TINYSESAM_GATE=ja` silently as "off" would mean a gate that keeps checking
    every request, and nobody would know why it does not get faster."""
    value = os.environ.get(name, "").strip().lower()
    if value in ("", "0", "false", "no", "off"):
        return False
    if value in ("1", "true", "yes", "on"):
        return True
    raise SystemExit(f"{name}={value!r}: expected 1 or 0 (true/false, yes/no, on/off)")


HEALTH_PATH = "/healthz"

#: How often the gateway runs `auth.gc()` (seconds): expired sessions, flows, one-time tokens and old sign-in attempts.
#: A library installation calls it from a timer (deploy/systemd/tinysesam-gc.*); the image has no cron, so the gateway
#: does it itself — at start and then every hour.
GC_INTERVAL_SEC = 3600


async def _housekeeping(auth) -> None:
    """`auth.gc()` now and every `GC_INTERVAL_SEC`, in a worker thread. A failure is logged, the loop goes on."""
    import asyncio
    while True:
        try:
            await asyncio.to_thread(auth.gc)
        except Exception as e:   # noqa: BLE001 — a full volume must not end the service; the next round retries
            security.seclog.error("Housekeeping (gc) failed: %s: %s", type(e).__name__, e)
        await asyncio.sleep(GC_INTERVAL_SEC)


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
    auth._install_hsts(app)
    return "force"


def _favicon() -> str:
    """TINYSESAM_BRAND_ICON: favicon of all pages of the gateway. Only from the own origin — a path (`/…`) or a
    `data:image/…` URI. A foreign URL would mean every visitor reports to third parties when loading the sign-in page."""
    value = os.environ.get("TINYSESAM_BRAND_ICON", "").strip()
    if value and not (value.startswith("data:image/") or (value.startswith("/") and not value.startswith("//"))):
        raise SystemExit("TINYSESAM_BRAND_ICON: only a path (/…) or a data:image/… URI — no foreign address")
    return value


def _background() -> list:
    """TINYSESAM_BRAND_BACKGROUNDS: background images, separated by spaces. An https address means: every
    visitor of the sign-in page loads from that third party. That works only with explicit approval
    (TINYSESAM_BRAND_BACKGROUNDS_EXTERN=1) — otherwise a startup error, so that it never happens by accident."""
    images = os.environ.get("TINYSESAM_BRAND_BACKGROUNDS", "").split()
    if any(b.startswith(("http://", "https://", "//")) for b in images) and not _switch("TINYSESAM_BRAND_BACKGROUNDS_EXTERN"):
        raise SystemExit("TINYSESAM_BRAND_BACKGROUNDS: foreign addresses only with TINYSESAM_BRAND_BACKGROUNDS_EXTERN=1 "
                         "(every visitor then loads from that third party)")
    return images


def _language() -> str:
    """TINYSESAM_LANG: one of the languages TinySesam ships with — otherwise a startup error instead of
    silent English pages."""
    from .messages import MESSAGES
    value = os.environ.get("TINYSESAM_LANG", "").strip().lower() or "en"
    if value not in MESSAGES:
        raise SystemExit(f"TINYSESAM_LANG={value!r}: known ones are {', '.join(sorted(MESSAGES))}")
    return value


def build_app(cfg: Optional[TinySesamConfig] = None):
    """Build the FastAPI app for the gateway (cfg optional; otherwise from env)."""
    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse
    auth = TinySesam(cfg or config_from_env())
    # No `/docs`, `/redoc` or `/openapi.json` (ASVS 13.4.5). FastAPI serves all three by default and without
    # sign-in: the schema maps every route including the admin API, and the Swagger page loads its
    # script and stylesheet from a third-party CDN without a CSP. Nobody operates the gateway through
    # them; whoever wants the schema reads it in Python (`build_app(cfg).openapi()`).
    # `lifespan`: at shutdown the background jobs finish before the database closes (T-67).
    import contextlib

    @contextlib.asynccontextmanager
    async def lifespan(app_):
        # Housekeeping for as long as the app runs (the image has no cron), then the ordered shutdown (T-67).
        import asyncio
        task = asyncio.create_task(_housekeeping(auth))
        try:
            async with auth.lifespan(app_):
                yield
        finally:
            task.cancel()

    app = FastAPI(title="TinySesam OIDC-Gateway", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.include_router(auth.router())
    # Browsers get the error page in the branding instead of `{"detail": "Not Found"}`; API clients
    # still get JSON (Accept decides, `install_error_pages`).
    auth.install_error_pages(app)

    @app.get("/", include_in_schema=False)
    def start_page(request: _Request):
        """Whoever opens the gateway's address does not land in the void: signed in, the overview with
        sign-out, otherwise the sign-in."""
        u = auth.session_user(request)
        if not u:
            return RedirectResponse(auth.browser_path(request, auth.cfg.login_path), 303)
        return auth.render_page("gateway_home", request=request, user_name=u["display_name"] or u["username"])

    show_version = _switch("TINYSESAM_HEALTH_VERSION")   # read at build time: a bad value ends the start

    @app.get(HEALTH_PATH, include_in_schema=False)
    def healthz():
        """Reachable without sign-in — otherwise no orchestrator could use it.

        Writes to the database once (`Store.write_probe()`). Very early on it only reported
        that the process is alive; after that it asked with `SELECT 1` — and that also succeeds on a
        read-only or full database (B6-4). After a rollback, on a full volume or
        wrong file permissions the service returned 500 to all users on sign-in, while
        Docker permanently kept the container as `healthy` — no restart, no alarm. A
        guard that cannot see the most likely failure is none.

        Reachable without sign-in also means: floodable. That is why the probe really writes at most every
        `Store.WRITE_PROBE_SEC`, in between it only checks the connection — otherwise
        every call would occupy the write lock that sign-ins wait for. Like any sign-in it waits
        up to `Store.BUSY_TIMEOUT_MS` behind a foreign writer; the HEALTHCHECK in the
        Dockerfile gives it more time for that.

        Nothing is revealed all the same: on a defect only `status: "degraded"` and 503, never
        the error message (which would otherwise stand unauthenticated on the network). Since T-52 not the
        version either (ASVS 13.4.6): it told everyone on the network which known flaws apply. Monitoring that
        wants it switches it on (`TINYSESAM_HEALTH_VERSION=1`); the image probe asks the package instead.
        """
        from fastapi.responses import JSONResponse

        def answer(status):
            if not show_version:
                return {"status": status}
            from . import current_version
            return {"status": status, "version": current_version()}
        try:
            auth.store.write_probe()
        except Exception as e:
            security.seclog.error("Healthcheck: database not writable (%s: %s)",
                                  type(e).__name__, e)
            return JSONResponse(answer("degraded"), status_code=503)
        return answer("ok")

    _install_https_except_health(auth, app)
    app.state.auth = auth
    return app


#: The two warnings uvicorn writes for every request with an `Upgrade` header it does not serve.
_UPGRADE_WARNINGS = ("Unsupported upgrade request.", "No supported WebSocket library detected.")


class _QuietUpgrade:
    """Drops uvicorn's upgrade warnings (B-5). The gateway speaks HTTP only: a forward-auth check of a
    WebSocket app arrives WITH the client's `Upgrade: websocket` (Caddy copies the headers) and is
    answered as a plain request. Logged, it was one warning pair per WebSocket connection — noise
    without a finding."""

    def filter(self, record) -> bool:
        return not record.getMessage().startswith(_UPGRADE_WARNINGS)


def _quiet_upgrade_warnings() -> None:
    import logging
    log = logging.getLogger("uvicorn.error")
    if not any(isinstance(f, _QuietUpgrade) for f in log.filters):
        log.addFilter(_QuietUpgrade())


def _server_config(app, host: str, port: int):
    """The uvicorn configuration of `python -m tinysesam.gateway`.

    `ws="none"` (B-5): with a WebSocket library installed (`websockets`, `wsproto`, e.g. via
    `uvicorn[standard]`), uvicorn takes a forward-auth check that carries `Upgrade: websocket` for a
    WebSocket handshake and answers 403 — every WebSocket app behind the gateway would be locked out.
    The gateway image had no such library, a pip install could. Created BEFORE the filter: the
    configuration sets up uvicorn's logging.

    `proxy_headers=False`: uvicorn applies X-Forwarded-For and -Proto by default (trusting `forwarded_allow_ips`,
    127.0.0.1 unless set). TinySesam reads them itself against `trusted_proxies` (`security.client_ip`); with
    uvicorn first, it judged an address uvicorn had already replaced, and `trusted_proxies` came to nothing."""
    import uvicorn
    config = uvicorn.Config(app, host=host, port=port, ws="none", proxy_headers=False)
    _quiet_upgrade_warnings()
    return config


def __getattr__(name):
    # Lazy `app`, so that `uvicorn tinysesam.gateway:app` works without import-time env,
    # but a plain `import tinysesam.gateway` (e.g. in tests) does NOT demand env right away.
    # Your own uvicorn invocation has configured its logging by now; it needs `--ws none` (B-5) and
    # `--no-proxy-headers` itself.
    if name == "app":
        _quiet_upgrade_warnings()
        return build_app()
    raise AttributeError(name)


HELP = """tinysesam.gateway — TinySesam as an OIDC forward-auth gateway

  python -m tinysesam.gateway          starts the service
  python -m tinysesam.gateway pair <account> [--create-service] [--resource URL]… [--name LABEL] [--roles a,b]
                                       a one-time pairing code for a service (T-60) — the gateway has no
                                       account page or admin panel to issue one; run it with the service's
                                       environment (docker exec <container> python -m tinysesam.gateway pair …)
  uvicorn tinysesam.gateway:app --ws none --no-proxy-headers
                                       the same via your own server invocation
                                       (--ws none: forward-auth checks of WebSocket apps;
                                       --no-proxy-headers: TinySesam reads X-Forwarded-For
                                       itself, against TINYSESAM_TRUSTED_PROXIES)

Installation:  pip install 'tinysesam[gateway]'   (not [oidc] — that is the library
                                                   without a server)

Configured via environment variables:
  TINYSESAM_OIDC_ISSUER          address of the provider          (required)
  TINYSESAM_OIDC_CLIENT_ID       client ID                        (required)
  TINYSESAM_OIDC_CLIENT_SECRET   client secret                    (required)
  TINYSESAM_BASE_URL             own public address               (required)
  TINYSESAM_PROTECTED_HOSTS      hosts behind the proxy, comma-separated
  TINYSESAM_COOKIE_DOMAIN        e.g. .example.com — for several hosts
  TINYSESAM_TRUSTED_PROXIES      network of the proxy, e.g. 172.28.0.0/16
  TINYSESAM_OIDC_CLIENTS         several applications as JSON (host → client)
  TINYSESAM_OIDC_CLIENT_<HOST>_ID / _SECRET   the same, one host at a time
  TINYSESAM_OIDC_REVALIDATE_MINUTES           re-check interval (default 60)
  TINYSESAM_DB                   path of the database
  TINYSESAM_HOST / _PORT         bind address (default 0.0.0.0:8000)

Example setup with Caddy: deploy/forward-auth/
"""


def _pair(argv) -> int:
    """`python -m tinysesam.gateway pair`: a pairing code through `create_service_pairing`, with the configuration of
    the running service (its environment) — resources, roles and audit as in the panel. Talks to no running process;
    the code is stored in the shared database and redeemed at the service's `/auth/oauth/pair`."""
    import argparse
    import datetime
    from .errors import ConfigError
    ap = argparse.ArgumentParser(prog="python -m tinysesam.gateway pair",
                                 description="Issue a one-time pairing code for a service (OAuth client_credentials).")
    ap.add_argument("account", help="the account the service acts as (usually a service account)")
    ap.add_argument("--create-service", action="store_true",
                    help="create a service account of that name if it does not exist")
    ap.add_argument("--resource", action="append", default=None,
                    help="a resource from TINYSESAM_OAUTH_RESOURCES (repeat; may be left out when there is one)")
    ap.add_argument("--name", default=None, help="label of the service, shown in the audit log and listings")
    ap.add_argument("--roles", default=None, help="comma list: a role scope within the account's roles")
    a = ap.parse_args(argv)
    with TinySesam(config_from_env()) as auth:
        user = auth.store.get_user_by_name(a.account)
        if user is None and a.create_service:
            auth.create_service(a.account)
            user = auth.store.get_user_by_name(a.account)
        if user is None:
            print(f"No account {a.account!r} (--create-service creates a service account).", file=sys.stderr)
            return 1
        roles = [r.strip() for r in a.roles.split(",") if r.strip()] if a.roles is not None else None
        try:
            issued = auth.create_service_pairing(int(user["id"]), name=a.name, resources=a.resource, roles=roles)
        except ConfigError as e:
            print(str(e), file=sys.stderr)
            return 1
    until = datetime.datetime.fromtimestamp(issued["expires_at"]).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    print(f"Pairing code for {a.account}: {issued['code']}  (once, until {until})")
    print(f"Resources: {', '.join(issued['resources'])}"
          + (f"  roles: {', '.join(issued['roles'])}" if issued["roles"] is not None else ""))
    if issued["dropped_roles"]:
        print(f"Not roles of the account, left out: {', '.join(issued['dropped_roles'])}")
    print(f"On the service:  tinysesam-client pair {issued['issuer']} {issued['code']}")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # `--help` BEFORE anything else: before, the question landed in the uvicorn import and then in
    # a server on 0.0.0.0:8000 — whoever wanted to know what the thing is called had it running.
    if argv and argv[0] in ("--help", "-h", "help"):
        print(HELP)
        return 0
    if argv and argv[0] == "pair":
        return _pair(argv[1:])
    if argv:
        print(f"Unknown argument: {argv[0]}\n", file=sys.stderr)
        print(HELP, file=sys.stderr)
        return 2
    try:
        import uvicorn
    except ModuleNotFoundError:
        # The README named `pip install 'tinysesam[oidc]'` and this start command in one
        # breath — yet [oidc] brings no server. The bare ModuleNotFoundError made
        # that look like a defect instead of a missing line in the install command.
        print("An ASGI server is missing to start.\n"
              "  pip install 'tinysesam[gateway]'\n"
              "Or bring your own:  uvicorn tinysesam.gateway:app --host 0.0.0.0 --port 8000 --ws none "
              "--no-proxy-headers",
              file=sys.stderr)
        return 1
    host = os.environ.get("TINYSESAM_HOST", "0.0.0.0")
    port = int(os.environ.get("TINYSESAM_PORT", "8000"))
    uvicorn.Server(_server_config(build_app(), host, port)).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
