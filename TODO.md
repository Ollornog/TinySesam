# TinySesam — TODO

## Forward-Auth-Modus (optional) — Proxy-Ebene, für fremde/nicht-änderbare Apps

**Motivation.** Aktuell schützt TinySesam **in-App, pro Route** (`Depends(auth.require_user)`) — ideal
für eigene FastAPI-Apps (paperlaiss). Für Apps/Seiten, die man **nicht anfassen** kann (statische
Sites, Fremd-Dienste, andere Container), fehlt der Reverse-Proxy-Weg à la **TinyAuth/Authelia**:
der Proxy schützt nach Pfad/Host und delegiert die Auth-Entscheidung an TinySesam.

**Kern.** Ein Verify-Endpoint, den Caddy `forward_auth` / nginx `auth_request` / Traefik `ForwardAuth`
pro Request aufruft:
- `GET /auth/forward` (bzw. `/auth/verify`):
  - eingeloggt (Session **oder** API-Key) → **200** + Header `Remote-User`, `Remote-Groups`, `Remote-Email`
    (der Proxy reicht sie an die Upstream-App durch).
  - nicht eingeloggt → **401**; Browser soll zum Login umgeleitet werden.
- Redirect-Handling wie TinyAuth: 401 **+ Header mit Login-URL** (z.B. `X-TinySesam-Location:
  https://auth.<domain>/auth/login?next=<orig-url>`), weil Caddys `forward_auth`-Shortcut die 401 nur
  durchreicht → **expandierte `reverse_proxy`-Form** mit `handle_response`/`redir` nötig
  (siehe Memory `tinyauth-pocketid-forward-auth`, gleicher Gotcha).

**Offene Punkte / Design.**
- **Cookie-Scope über Domains:** Session-Cookie muss für alle geschützten Hosts gelten → Cookie-Domain
  auf gemeinsame Parent-Domain (`.example.com`) **oder** Redirect-SSO-Handshake über eine zentrale
  `auth.<domain>`. `config.cookie_domain` ergänzen.
- **Login zentral erreichbar:** TinySesam-Login muss unter einer eigenen Domain/Subdomain laufen
  (eigener Mount/Port — ist mit `admin_router()`/eigenem Mount schon vorbereitet).
- **`next`-Redirect** absichern (nur erlaubte Hosts/relative Pfade → Open-Redirect vermeiden).
- **Config:** `forward_auth_enabled`, `cookie_domain`, `trusted_redirect_hosts`.
- **Beispiel-Configs** nach `deploy/`: Caddy (`forward_auth` expandiert), nginx (`auth_request`),
  Traefik (ForwardAuth-Middleware).
- **Access-Header** optional per Config (welche `Remote-*` gesetzt werden).

**Abgrenzung.** Ergänzt den bestehenden In-App-Modus (beide koexistieren); ändert nichts am
Embedded-Betrieb. Härtung/Audit/API-Keys/2FA gelten dann auch für den Forward-Auth-Pfad.
