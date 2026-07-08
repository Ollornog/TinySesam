# Changelog

Alle nennenswerten Änderungen. Format lose nach [Keep a Changelog](https://keepachangelog.com/de/).

## [0.8.0] — 2026-07-09

### Hinzugefügt
- **SAML 2.0 SP-Login** (Extra `[saml]`, python3-saml) — `/auth/saml/login|acs|metadata`, Signatur-
  geprüfte Assertion (ACS von CSRF ausgenommen), Attribute→User, Gruppen-Gate, Faktor `saml`.
- **Presets** — `TinySesamConfig.active_directory(...)` (AD via LDAP, UPN- oder sAMAccountName-Bind)
  und `TinySesamConfig.entra_id(...)` (Azure AD/Entra via OIDC).
- README/Website: problem-orientierter Pitch (Login-Layer für selbstgebaute Apps).

### Hinweis
Kerberos/NTLM/GSSAPI-SSO bleibt bewusst außen vor (LAN-/domänengebunden, schwere Ops-Kopplung,
redundant zu OIDC/SAML für AD).

## [0.7.0] — 2026-07-08

### Hinzugefügt
- **i18n** — eingebaute Texte in **Englisch (neuer Default)** und **Deutsch**; `config.lang`,
  `auth.t(key)`, `auth.add_messages(lang, {...})`. **Achtung:** Default ist jetzt Englisch —
  deutschsprachige Integrationen setzen `lang="de"`.
- **CSRF-Schutz** (Double-Submit-Cookie, `csrf_enabled`, Default an) auf allen state-ändernden POSTs;
  eingebaute Formulare/JS erledigen es automatisch, API-Key-Requests sind ausgenommen.
- **Prozessübergreifendes Rate-Limit** über Redis (`redis_url`, Extra `[redis]`) für Multi-Worker;
  `auth.set_rate_limiter()` für eigene Backends. Fallback In-Memory, fail-open bei Redis-Ausfall.
- Projekt-**Icon** + minimale **GitHub-Pages-Website** (`docs/`).

## [0.6.0] — 2026-07-08

### Hinzugefügt
- **LDAP/lldap-Backend** (Extra `[ldap]`) — Passwort gegen Verzeichnis-Bind (Direkt- oder Search-then-Bind),
  Auto-Create lokaler User, optionales Gruppen-Gate. Koexistiert mit lokalen Passwörtern.
- **TOTP-Recovery-Codes** — Einmal-Codes als 2FA-Ersatz (im TOTP-Schritt einlösbar, Self-Service-Regenerierung).
- **Forgot-Password** — Self-Service-Reset per E-Mail (`password_reset_enabled`, nutzt Magic-Link/Mailer).
- **Eigene Sitzungen verwalten** — `/auth/sessions` (maskiert) + „andere/überall abmelden"; auf der Konto-Seite.
- **Optionaler OIDC-RP-Logout** (`oidc_rp_logout`) — Abmelden auch beim Provider (`end_session`).
- `auth.gc()` (DB-Housekeeping), `py.typed` (Typinfos werden mitgeliefert).

### Härtung
- Sessions werden nach Passwortwechsel invalidiert (Self: außer aktueller; Admin-Reset: alle).
- Dummy-Hash-Verify gegen **User-Enumeration** per Timing (Login & PIN).
- Ungültiger JSON-Body → **400** statt 500. Test-Runner `tests/run_all.py` + CI (Py 3.10–3.13).

## [0.5.0] — 2026-07-08

Großer Feature-Ausbau; alles **optional** (per Config an/aus), einzeln und kombiniert nutzbar,
Frontend über eine Template-Registry komplett austauschbar. Der klassische Pfad (ein Erstfaktor +
TOTP falls eingerichtet) bleibt unverändert.

### Hinzugefügt
- **Template-Override-Registry** (`auth.set_template(name, fn)`) — jede Seite ersetzbar (String oder Response).
- **Remember-me** — persistentes vs. reines Session-Cookie (`remember_me_enabled`, `session_ttl_transient_hours`).
- **Step-up / per-Route-MFA** — `auth.require(mfa=True)`, Sudo-Frische `stepup_max_age_sec`, `/auth/reauth`, `admin_require_mfa`.
- **Faktor-Ketten** (geordnet) — global `login_chain` + per Route `require(factors=[...], strict=...)`; z.B. OIDC→Passwort.
- **Persönliche PIN** pro User (`pin_enabled`), eigener strenger Lockout, mit TOTP kombinierbar.
- **Geteiltes Ressourcen-Geheimnis** (PIN/Passphrase, ohne Konto) — `require_resource(name)`.
- **Magic-Link** (Einmal-Login per E-Mail) + **Mailer-Hook** (`set_mailer`) / SMTP.
- **Registrierung + Einladung** — `allow_signup`, `signup_verify_email`, `signup_invite_only`, `create_invite`.
- Eingebaute **Konto-Seite** `/auth/account` + Selbst-Passwortänderung `/auth/password`.
- **Forward-Auth** (`/auth/forward` + `/auth/verify`) für Reverse-Proxys; Beispiele Caddy/nginx/Traefik.
- **OIDC-Gateway-Preset** — `TinySesamConfig.oidc_gateway(...)`, `python -m tinysesam.gateway`, docker-compose.
- **Test-Runner** `tests/run_all.py` + **GitHub-Actions-CI** (Py 3.10–3.13, voll + Minimal-Lauf).

### Geändert / Härtung
- Zentraler **Open-Redirect-Schutz** `safe_next` auf allen `?next=`-Zielen; `cookie_domain` für Subdomain-SSO.
- Ungültiger JSON-Body → **400** statt 500 (`TinySesam.json_body`).
- Store-Auto-Migration (`session.mfa_at`/`remember`/`factors_done`), neues Modul `mailer.py`.

## [0.4.0] — 2026-07-06
Admin-Panel als eigenständiger, frei montierbarer Router (Prefix/Subdomain/Port) + nur-JSON-API-Modus;
HTTPS-Modi `off`/`warn`/`force`.

## [0.3.0] — 2026-07-06
API-Keys + Service-/Daemon-Accounts (gehasht, Ablauf, Rollen-Scope) + eingebautes Admin-Panel.

## [0.2.0] — 2026-07-06
Härtung (Brute-Force-Lockout, Rate-Limit, fail2ban-Log, Audit, Trusted-Proxy) + Self-Update von GitHub.

## [0.1.0] — 2026-07-06
Erstversion: Passwort + TOTP + Passkey/WebAuthn + OIDC, server-seitige Sessions, optionale Rollen.
