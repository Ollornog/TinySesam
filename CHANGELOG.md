# Changelog

Alle nennenswerten Änderungen. Format lose nach [Keep a Changelog](https://keepachangelog.com/de/).

## [Unreleased]

### Hinzugefügt
- **Login-Kennung wählbar** — `login_identifier="username" | "email" | "both"` (Default **`both`**).
  Passwort- und PIN-Login gehen über `auth.find_user(...)`; das Kennungsfeld beschriftet sich
  passend („Benutzer" / „E-Mail" / „Benutzer oder E-Mail"). Der Timing-Schutz gegen
  User-Enumeration (Dummy-Hash) bleibt in allen Modi erhalten.
- **E-Mail als vollwertige Kennung** — `signup_require_email` (Default **an**), Formatprüfung,
  kanonische Speicherung (getrimmt/klein) und **Eindeutigkeit** per partiellem UNIQUE-Index
  (`users(lower(email))`, Konten ohne Adresse bleiben erlaubt). `store.norm_email`/`valid_email`/`email_taken`.
- **Registrierung folgt `login_identifier`:** im Modus `"email"` entfällt das Benutzernamen-Feld,
  die Adresse ist die Kennung; sonst wie gehabt. Das Admin-Panel darf den Namen dort ebenfalls weglassen.
- Admin-Panel: E-Mail beim Anlegen (Pflicht folgt der Config) + eigene Spalte in der Benutzertabelle.
- **`brand_icon`** — Favicon für **alle** eingebauten Seiten aus einem Config-Wert (Login/PIN/TOTP/
  Konto/Register/Magic/Admin-Panel/Fehlerseiten). Vorher hatte keine davon eins.
- Showcase: **Demo-Postfach** (`/demo/postfach`) — die Demo verschickt nichts, `set_mailer` legt die
  Mails dort ab. Login-Link und Passwort-vergessen sind damit wirklich ausprobierbar.
- **PIN ohne Login-Rolle** — `pin_login=False`: die PIN existiert, erscheint aber **nicht** auf der
  Login-Seite. Sie dient dann nur als Zusatzfaktor (`require(factors=[…, "pin"])`) oder als Step-up.
- **Step-up mit PIN** — `stepup_methods=["pin"]` (leer = alles, was der User hat: TOTP → PIN → Passwort).
  `/auth/reauth` konnte bisher nur TOTP oder Passwort; jetzt auch PIN, und `auth.stepup_options(user)`
  sagt, was für den jeweiligen Nutzer in Frage kommt (Fallback, falls die Wunschmethode fehlt).
- **`/auth/pin` für Eingeloggte** — GET rendert eine echte PIN-Seite (bisher: Redirect auf die Login-Seite),
  ohne Benutzerfeld, wenn eine Sitzung läuft; POST leitet die Identität aus der Sitzung ab.
  Neues Template `pin`, `auth.verify_user_pin` / `verify_user_password` prüfen gegen eine bekannte Identität.
- **Preset `TinySesamConfig.local_accounts(...)`** — nur Benutzername + Passwort, ganz ohne E-Mail
  (kein Magic-Link, kein Passwort-vergessen, keine Bestätigung). Das Registrierungsformular zeigt
  **kein E-Mail-Feld mehr**, wenn die App mit der Adresse ohnehin nichts anfängt.
- Showcase: Seite **`/demo/flows`** — die Login-Wege als Diagramm; „aktiv/aus" liest sie aus der
  laufenden Config. Neue Suite `tests/test_pin_stepup.py`.
- `signup_verify_email` ist jetzt belastbar: Bestätigung an, aber **kein Mailer** konfiguriert →
  klarer Fehler statt stillem Durchwinken; es wird auch **kein halbfertiges Konto** angelegt.
  Neue Suite `tests/test_identifier.py`.

### Hinzugefügt (Showcase & Design)
- **Showcase-Frontend** (`examples/showcase.py`): `/` ist die Projekt-Website (`docs/index.html`)
  **eins zu eins**, ergänzt um einen Demo-Knopf. `/demo` ist das Demo-Frontend — Nav mit Logo und Titel,
  Anmelden/Registrieren, darunter Login-, Konto- und Admin-Panel als **read-only Live-Vorschau**.
  Die Vorschauen rendern die **echten** Bausteine (`auth.render_page(...)`, `admin.render_panel(...)`),
  sind also nie veraltet; die Admin-Vorschau läuft gegen eine lesende Attrappen-API.
- `tinysesam.admin.render_panel(auth, base, warn="")` — öffentlich, damit das Panel-HTML an genau
  einer Stelle erzeugt wird (Panel und Demo-Vorschau können nicht auseinanderlaufen).
- Showcase: zweite Nav-Leiste mit den Testseiten; Konto und Admin-Panel erscheinen erst, wenn man
  angemeldet ist bzw. Admin-Rechte hat. GitHub-/Doku-Knöpfe mit Icon.

### Geändert
- **Alle eingebauten Seiten stylen sich jetzt über CSS-Variablen** (neu: `tinysesam/theme.py`).
  Login, Konto und Admin-Panel hatten je eigene, hart kodierte Farben — ein `brand_css` konnte sie
  nicht vollständig überschreiben (Konto/Panel blieben dunkel). Ein Satz Tokens re-skinnt nun alles.
  Aussehen der Defaults unverändert (dunkles Theme).
- Website und Showcase teilen sich die Palette `docs/theme.css` (die Website lädt sie per `<link>`,
  die App reicht sie als `brand_css` weiter).
- **README zweisprachig**: `README.md` (Englisch, Default) + `README.de.md` (Deutsch), mit Sprachumschalter.

### Behoben
- Showcase: „Anmelden"/„Konto erstellen" wirkten im eingeloggten Zustand tot (`/auth/login` → `303 /`).
  Das Demo-Frontend kennt jetzt den Login-Status und zeigt stattdessen Konto/Abmelden.

## [0.10.0] — 2026-07-09

### Hinzugefügt
- **Zentraler Theming-Hook:** `brand_css` / `brand_head` re-skinnen mit einem Config-Wert ALLE
  eingebauten Seiten (Login/PIN/TOTP/Reauth/Magic/Register/Konto/Admin-Panel) — kein Nachbau je Seite.
- **Themed Fehlerseiten:** `auth.install_error_pages(app)` — 403/404/429/500 als gebrandete HTML-Seite
  für Browser, JSON für API-Clients; Redirects (Login/Reauth/Faktor) bleiben Redirects. `error`-Template
  über `set_template('error')` ersetzbar.
- Admin-Panel: **„Jetzt aktualisieren"** immer verfügbar (nicht nur bei erkanntem Update).
- Showcase: vollständig gebrandetes Beispiel (ein `brand_css`) inkl. 404-/500-Demo.

## [0.9.0] — 2026-07-09

### Hinzugefügt
- **Rollen/Gruppen-Verwaltung:** `available_roles` (bekannte Rollen) → Admin-Panel bietet sie als
  **Checkboxen** je User (Fallback Freitext). `auth.apply_idp_groups(...)`.
- **IdP-Gruppen → lokale Rollen:** `oidc_group_role_map` / `saml_group_role_map` / `ldap_group_role_map`
  (Teilstring-Match, Ziel `__admin__` setzt Admin-Flag). Beim Login gesetzt; gemappte Rollen werden
  synchronisiert, manuelle bleiben. Konsistente `require_role(...)`-Autorisierung über alle Login-Wege.

### Behoben
- CI: `[all]`-Job installiert `libxmlsec1-dev` (SAML/xmlsec); Test-Runner überspringt Suiten mit
  fehlenden Extras (onelogin/ldap3/redis/xmlsec) statt zu scheitern (Minimal-Job wieder grün).

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
