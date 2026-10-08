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
    TINYSESAM_ALLOWED_GROUPS                   Komma-Liste. Leer = JEDES Konto beim Provider kommt
                                               durch das Tor — ohne Freigabe je Client (unten)
                                               warnt der Start deshalb laut (B3-9)
    TINYSESAM_OIDC_NAME                        Beschriftung des Anmelde-Knopfs (Default "SSO"), z. B. "PocketID"
    TINYSESAM_BRAND_ICON                       Favicon aller Seiten: Pfad (/…) oder data:image/…-URI, nie eine fremde URL
    TINYSESAM_BRAND_BACKGROUNDS                Hintergrundbilder (Leerzeichen-getrennt), blenden über; sehr dunkel abgedeckt
    TINYSESAM_BRAND_BACKGROUNDS_EXTERN         1 = https-Adressen erlaubt (Abruf bei Dritten; sonst Startfehler)
    TINYSESAM_BRAND_BACKGROUND_SECONDS         Standzeit je Bild (Default 12)
    TINYSESAM_BRAND_BACKGROUND_CREDIT_TEXT/URL Dezenter Hinweis unten rechts, z. B. "Fotos: Unsplash"
    TINYSESAM_GATE_BRAND                       Marke vor den Anwendungen: Anmeldeseite „Anmelden bei <Marke>“
                                               mit „App: <Name>“ darunter (leer = „Anmelden bei <Name>“)
    TINYSESAM_OIDC_SCOPES                      Default "openid profile email". Mit Gruppen bei
                                               PocketID u. a.: "openid profile email groups" —
                                               ohne den Scope fehlt der Claim, und das Tor weist
                                               jeden ab (der Start warnt)
    TINYSESAM_TRUSTED_PROXIES                  Komma-Liste; Default 127.0.0.1/32,::1/128
    TINYSESAM_OIDC_CLIENTS                     JSON: mehrere Anwendungen, je eine mit eigenem
                                               Client beim selben Provider (T-14). Beispiel:
                                               {"app.example.com": {"client_id": "...",
                                                "client_secret": "..."}}
                                               Alternativ je Host zwei Variablen, siehe unten.
    TINYSESAM_OIDC_REVALIDATE_MINUTES          Frist, nach der die Freigabe beim Provider
                                               nachgeprüft wird (Default 60, 0 = nie)
    TINYSESAM_GATE                             1 = Gate-Token ausstellen (ADR-9): der Proxy prüft
                                               danach selbst, Vorlage deploy/forward-auth/Caddyfile.gate
                                               (braucht Caddy mit caddy-jwt). Default 0
    TINYSESAM_GATE_LINK                        1 = zentrales Gateway mit Code-Austausch (T-26): Sitzung
                                               bleibt auf TINYSESAM_BASE_URL, jeder App-Host bekommt nur
                                               ein eigenes Verbindungs-Cookie. Verlangt TINYSESAM_GATE=1
                                               und KEIN TINYSESAM_COOKIE_DOMAIN. Default 0
    TINYSESAM_GATE_TTL_SEC                     Laufzeit des Gate-Tokens (Default 300, 30–3600) —
                                               so lange wirkt ein Widerruf am Proxy nicht
    TINYSESAM_FORWARD_LOGIN                    direct (Default: Seitenaufruf → Provider → zurück) oder
                                               page (erst die Login-Seite mit dem Namen der Anwendung)
    TINYSESAM_FORWARD_LOGOUT                   all (Default: Sitzung und Provider), app (nur diese
                                               Anwendung) oder ask (fragen) — Weg /.tinysesam/logout
    TINYSESAM_FORWARD_APPS                     JSON je Anwendung: {"wiki.example.com": {"name": "Wiki",
                                               "login": "page", "logout": "ask"}} — name erscheint
                                               auf Login- und Abmeldeseite
    TINYSESAM_DB                               Default tinysesam-gateway.db
    TINYSESAM_HTTPS_MODE                       off|warn|force (Default warn)
    TINYSESAM_LANG                             Sprache der Seiten des Gateways: en (Default) oder de
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


from starlette.requests import Request as _Request  # Modulebene: FastAPI muss die Annotation auflösen

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
        gate_token_ttl_sec=int(os.environ.get("TINYSESAM_GATE_TTL_SEC", "300") or 300),
    )


def _json_objekt(name: str) -> dict:
    """Ein JSON-Objekt aus der Umgebung, leer = {}. Kaputtes JSON beendet den Start — still
    ignoriert gälte für jede Anwendung die Vorgabe, und niemand sähe, warum."""
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
    """Ein Ein/Aus aus der Umgebung. Ein Wert, der weder das eine noch das andere ist, beendet
    den Start: `TINYSESAM_GATE=ja` still als „aus" zu lesen, hiesse ein Gate, das jede Anfrage
    weiter prüft, und niemand wüsste, warum es nicht schneller wird."""
    wert = os.environ.get(name, "").strip().lower()
    if wert in ("", "0", "false", "no", "off"):
        return False
    if wert in ("1", "true", "yes", "on"):
        return True
    raise SystemExit(f"{name}={wert!r}: erwartet 1 oder 0 (true/false, yes/no, on/off)")


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


def _favicon() -> str:
    """TINYSESAM_BRAND_ICON: Favicon aller Seiten des Gateways. Nur vom eigenen Ursprung — ein Pfad (`/…`) oder eine
    `data:image/…`-URI. Eine fremde URL hiesse, jeder Besucher meldet sich beim Laden der Anmeldeseite bei Dritten."""
    wert = os.environ.get("TINYSESAM_BRAND_ICON", "").strip()
    if wert and not (wert.startswith("data:image/") or (wert.startswith("/") and not wert.startswith("//"))):
        raise SystemExit("TINYSESAM_BRAND_ICON: nur ein Pfad (/…) oder eine data:image/…-URI — keine fremde Adresse")
    return wert


def _hintergruende() -> list:
    """TINYSESAM_BRAND_BACKGROUNDS: Hintergrundbilder, durch Leerzeichen getrennt. Eine https-Adresse heisst: jeder
    Besucher der Anmeldeseite laedt bei diesem Dritten. Das geht nur mit ausdruecklicher Freigabe
    (TINYSESAM_BRAND_BACKGROUNDS_EXTERN=1) — sonst Startfehler, damit es nie aus Versehen passiert."""
    bilder = os.environ.get("TINYSESAM_BRAND_BACKGROUNDS", "").split()
    if any(b.startswith(("http://", "https://", "//")) for b in bilder) and not _schalter("TINYSESAM_BRAND_BACKGROUNDS_EXTERN"):
        raise SystemExit("TINYSESAM_BRAND_BACKGROUNDS: fremde Adressen nur mit TINYSESAM_BRAND_BACKGROUNDS_EXTERN=1 "
                         "(jeder Besucher laedt dann bei diesem Dritten)")
    return bilder


def _sprache() -> str:
    """TINYSESAM_LANG: eine der Sprachen, die TinySesam mitbringt — sonst ein Startfehler statt
    stiller englischer Seiten."""
    from .messages import MESSAGES
    wert = os.environ.get("TINYSESAM_LANG", "").strip().lower() or "en"
    if wert not in MESSAGES:
        raise SystemExit(f"TINYSESAM_LANG={wert!r}: bekannt sind {', '.join(sorted(MESSAGES))}")
    return wert


def build_app(cfg: Optional[TinySesamConfig] = None):
    """FastAPI-App für das Gateway bauen (cfg optional; sonst aus Env)."""
    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse
    auth = TinySesam(cfg or config_from_env())
    app = FastAPI(title="TinySesam OIDC-Gateway")
    app.include_router(auth.router())
    # Browser bekommen die Fehlerseite im Branding statt `{"detail": "Not Found"}`; API-Clients
    # weiter JSON (Accept entscheidet, `install_error_pages`).
    auth.install_error_pages(app)

    @app.get("/", include_in_schema=False)
    def startseite(request: _Request):
        """Wer die Adresse des Gateways aufruft, landet nicht im Leeren: angemeldet die Übersicht mit
        Abmelden, sonst die Anmeldung."""
        u = auth.session_user(request)
        if not u:
            return RedirectResponse(auth.browser_path(request, auth.cfg.login_path), 303)
        return auth.render_page("gateway_home", request=request, user_name=u["display_name"] or u["username"])

    @app.get(HEALTH_PATH, include_in_schema=False)
    def healthz():
        """Ohne Anmeldung erreichbar — sonst könnte kein Orchestrator ihn benutzen.

        Schreibt einmal in die Datenbank (`Store.schreibprobe()`). Ganz früher meldete er nur,
        dass der Prozess lebt; danach fragte er mit `SELECT 1` — und das gelingt auch auf einer
        nur lesbaren oder vollen Datenbank (B6-4). Nach einem Rollback, bei vollem Volume oder
        falschen Dateirechten lieferte der Dienst allen Nutzern beim Anmelden 500, während
        Docker den Container dauerhaft als `healthy` führte — kein Neustart, kein Alarm. Ein
        Wächter, der den wahrscheinlichsten Ausfall nicht sehen kann, ist keiner.

        Ohne Anmeldung erreichbar heisst auch: flutbar. Deshalb schreibt die Probe höchstens alle
        `Store.SCHREIBPROBE_SEK` wirklich, dazwischen prüft sie nur die Verbindung — sonst belegte
        jeder Aufruf die Schreibsperre, auf die Anmeldungen warten. Sie wartet wie jede Anmeldung
        bis zu `Store.BUSY_TIMEOUT_MS` hinter einem fremden Schreiber; der HEALTHCHECK im
        Dockerfile gibt ihr dafür mehr Zeit.

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
