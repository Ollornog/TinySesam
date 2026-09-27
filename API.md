# API — die öffentliche Oberfläche von `TinySesam`

<!-- GENERIERT von scripts/_api_doku.py — nicht von Hand pflegen.
     Neu bauen: `python3 scripts/_api_doku.py` -->

Diese Namen hält `tests/api_surface.json` fest, jeden mit seiner **Stufe**: Was hier steht,
ändert sich nicht ohne eine bewusste Entscheidung und einen Eintrag im CHANGELOG.

Die READMEs zeigen die **Wege** (welche Methode wofür, wie man sie kombiniert). Hier steht, was
es überhaupt gibt — die Frage „gibt es dafür schon etwas?" beantwortet diese Seite, nicht der
Quelltext.

## Drei Stufen — was zugesagt ist

| Stufe | Was | Zusage |
|---|---|---|
| **A — öffentlich, stabil ab 1.0** | dokumentiert und/oder von Einbettenden genutzt | Kein Bruch über zwei Minor-Versionen — die Bedingung für 1.0 ([M-1](backlog/M-1-api-stabil-1-0.md)). Der Zähler startet mit 0.22.0, dem Release, das die Einstufung bringt. |
| **B — für Fortgeschrittene** | Bausteine für eigene Konto- und Admin-Seiten, eigene Mail- und Token-Abläufe, Erweiterungspunkte | Bleibt. Entfernen oder umbauen erst, nachdem eine `DeprecationWarning` zwei Minor-Versionen lang darauf hingewiesen hat. Schwächer als A: Ein Umbau mit Vorlauf ist erlaubt. |
| **C — intern** | Verdrahtung der eingebauten Routen | Keine. Die Implementierung trägt seit 0.22.0 einen führenden Unterstrich; der alte Name bleibt bis 1.0 als Alias, der beim Aufruf eine `DeprecationWarning` auslöst, und fällt dann weg. |

Die Stufe steht je Name in `tests/api_surface.json`. Der Wächter `tests/test_api_surface.py` verlangt für jeden öffentlichen Namen eine ausdrückliche: Ein neuer Name kommt ohne Stufe herein und hält ihn rot, bis jemand entscheidet — nichts wird aus Versehen zugesagt.

Die Konfigurationsfelder stehen in [KONFIGURATION.md](KONFIGURATION.md): 158 von 159 in Stufe A, die übrigen unten bei ihrer Stufe.

**Stand:** A 240 · B 64 · C 50 Namen.

## A · Methoden von `TinySesam`

### `add_messages(lang, mapping: 'dict')`

Eigene Übersetzungen ergänzen/überschreiben (haben Vorrang vor den eingebauten).

### `admin_router()`

Eigenständiger Admin-Router (relative Pfade) — an beliebigem Prefix / Sub-App / Port montierbar, oder (admin_ui_enabled=False) nur die JSON-API fürs eigene Panel.

### `anmelden_passwort(request: 'Request', username: 'str', password: 'str', next: 'str' = '', remember: 'Optional[bool]' = None, csrf: 'Optional[str]' = None) -> 'Anmeldung'`

Mit Kennung und Passwort anmelden — gedrosselt, gezählt und gesperrt wie `POST /auth/login`, die genau diese Methode ruft.

### `anmelden_pin(request: 'Request', pin: 'str', username: 'str' = '', next: 'str' = '', remember: 'Optional[bool]' = None, csrf: 'Optional[str]' = None) -> 'Anmeldung'`

Mit der persönlichen PIN anmelden oder den PIN-Schritt erbringen — gedrosselt und gesperrt wie `POST /auth/pin`, die genau diese Methode ruft.

### `anmelden_totp(request: 'Request', code: 'str', next: 'str' = '', csrf: 'Optional[str]' = None) -> 'Anmeldung'`

Den TOTP-Schritt erbringen — mit einem TOTP-Code oder einem Einmal-Code, gedrosselt und gesperrt wie `POST /auth/totp`, die genau diese Methode ruft.

### `change_username(user_id, neu, ip: 'Optional[str]' = None, durch_betreiber: 'bool' = False) -> 'str'`

Den eigenen Benutzernamen ändern. Gibt den neuen Namen zurück, `ValueError` mit dem Grund, wenn er nicht geht.

### `complete_totp(token) -> 'Optional[str]'`

Den TOTP-Schritt abschließen: Faktor `totp` an die laufende Sitzung anhängen. Gibt ein neues Sitzungs-Token zurück, das ins Cookie gehört (`neu = auth.complete_totp(token)`, `if neu: auth.set_cookie(resp, neu)`) — das alte ist danach tot, auch beim Step-up.

### `create_api_key(user_id, name=None, expires_days=None, roles=None, kind: 'str' = 'automat') -> 'dict'`

Neuen API-Key erzeugen. Rückgabe enthält 'key' im KLARTEXT — nur EINMAL (danach nur der Hash).

### `create_invite(email, base_url, roles=None, is_admin=False, ttl_min=None) -> 'dict'`

Einladung erzeugen (+ optional versenden). Rückgabe {url, token}. Der Token trägt die vorgesehenen Rollen/Adminrechte; eingelöst wird er erst bei der Registrierung. `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

### `create_service(username, roles=None, display_name=None) -> 'int'`

Service-/Daemon-Account: kein interaktiver Login, nur API-Keys. Rollen = Rechte-Scope.

### `create_user(username, password=None, is_admin=False, roles=None, display_name=None, email=None, is_service=False, email_verified: 'bool' = True, name_selbst_gewaehlt: 'bool' = False) -> 'int'`

Ein Konto anlegen und seine ID zurückgeben. `is_service=True` für Maschinen: kein Login, nur API-Keys. Eine bereits vergebene Kennung wirft `ConfigError` — **neu auch beim doppelten Benutzernamen**, der bis 0.18.x als `sqlite3.IntegrityError` aus der Datenbank kam (`e.feld`/`e.besitzer_id` sagen, was kollidierte).

### `csrf_token(request: 'Optional[Request]' = None) -> 'str'`

Das CSRF-Token dieses Browsers — vorhandenes Cookie wiederverwenden, sonst neu würfeln.

### `current_user(request) -> 'Optional[dict]'`

Das angemeldete Konto zu diesem Request — aus der Sitzung ODER einem API-Key. None, wenn niemand angemeldet ist.

### `ensure_admin(username, password) -> 'bool'`

Bootstrap: legt einen Admin an, WENN noch kein User existiert. True bei Anlage.

### `ensure_csrf(request: 'Request', response: 'Response') -> 'str'`

Ein gültiges CSRF-Cookie sicherstellen und das Token fürs Formular zurückgeben.

### `foederation_nachbinden(quelle: 'str', zuordnung: 'Optional[dict]' = None, ausfuehren: 'bool' = False) -> 'dict'`

Bestandskonten an ihre Kennung in LDAP/SAML binden, ohne auf ihre Anmeldung zu warten (G1).

### `gc(attempts_older_than_sec: 'int' = 86400) -> 'dict'`

Aufräumen: abgelaufene Sessions/Flows/Magic-Tokens/Ressourcen-Unlocks + alte Login-Versuche. Regelmäßig aufrufen (Cron/Startup/Scheduler) — sonst wachsen die Tabellen. Das Audit-Log nur, wenn `audit_retention_days` eine Frist setzt (B5-11) — dann steht die Zahl unter `audit`. Gibt Anzahl gelöschter Zeilen je Bereich. `attempts_older_than_sec` liegt zwischen 0 (alle Fehlversuche) und zehn Jahren in Sekunden, sonst `ValueError`, bevor irgendetwas gelöscht wird.

### `grant_mfa_enrollment(user_id: 'int', minutes: 'int' = 60) -> 'int'`

Ein Einrichtungsfenster öffnen und seinen Ablauf zurückgeben.

### `has_role(user, role, admin_implies=None) -> 'bool'`

Hat der User die Rolle? Ein Admin erfüllt standardmäßig JEDE Rolle (`config.admin_implies_roles`). Wer Rechte allein an IdP-Gruppen hängt, schaltet das ab — sonst ist jeder lokale Admin automatisch auch „editor", „viewer", … .

### `install_error_pages(app)`

Themed Fehlerseiten registrieren (opt-in). Browser bekommen die 'error'-Seite (im Branding), API-Clients JSON; Redirects (Login/Reauth/Faktor, via Location-Header) bleiben Redirects.

### `install_https(app)`

HTTPS gemäß config.https_mode: 'force' → HTTP→HTTPS-Redirect-Middleware; 'warn'/'off' → läuft auch OHNE Zertifikat (bei 'warn' Panel-Hinweis). Gibt den Modus zurück.

### `is_admin(user) -> 'bool'`

Ist dieses Konto Admin? Nimmt eine Kontozeile, kein Request.

### `issue_csrf(response: 'Response') -> 'str'`

Ein NEUES CSRF-Token würfeln und als Cookie setzen; Rückgabe ist das Token. Für eine Seite mit Formular ist `ensure_csrf()` der Weg — dieses hier entwertet die Formulare in allen anderen offenen Reitern.

### `loese_fremde_bindung(quelle: 'str', user_id: 'int') -> 'int'`

Die Bindung eines Kontos an eine fremde Identität lösen (Betreiber-Weg) — und die Bindung über den Namen für die nächste Anmeldung öffnen. Gibt die Zahl der gelösten Bindungen zurück (0: das Konto war nicht gebunden).

### `login_fresh(request: 'Request', user: 'Optional[dict]' = None) -> 'bool'`

True, wenn die **Anmeldung** höchstens `stepup_max_age_sec` zurückliegt.

### `logout(request, response)`

Die Sitzung dieses Requests beenden, die Bereichs-Freigaben dieses Browsers mit, und die Cookies löschen — Sitzung, Freigabe und seit 0.20.1 auch das CSRF-Cookie, dazu die Cookies unter den Namen von vor dem `__Host-`-Präfix.

### `public_base(request: 'Optional[Request]' = None, kandidat: 'str' = '') -> 'str'`

Die öffentliche Basis-URL für alles, was das Haus verlässt — Mail-Links, Redirect-URIs, SAML-Metadaten. Leer heißt: es gibt keine, der Aufrufer bricht ab.

### `render_page(template, status=200, request: 'Optional[Request]' = None, **ctx) -> 'Response'`

`request` mitgeben, wo es eins gibt: dann bleibt ein bereits gesetztes CSRF-Token gültig. Ohne `request` entsteht ein neues — das überschreibt das Cookie und macht *andere* offene Formulare ungültig (klassische „Formular abgelaufen"-Falle).

### `require(mfa: 'bool' = False, admin: 'bool' = False, role=None, factors: 'Optional[list]' = None, strict: 'Optional[bool]' = None, admin_implies: 'Optional[bool]' = None)`

Allgemeine Guard-Factory für beliebige Kombinationen — der „Flag am Guard"-Weg: `Depends(auth.require(mfa=True))`, `Depends(auth.require(admin=True, mfa=True))`. `role=` nimmt eine Rolle oder mehrere (`role=["redaktion", "lektorat"]` → eine genügt). factors=[...] verlangt für diese Route zusätzlich eine bestimmte Faktor-Kette, strict=True/False steuert die Reihenfolge: `Depends(auth.require(factors=['oidc','password']))`. Die Route-Kette verschärft die globale Regel, sie ersetzt sie nicht: Eine Sitzung, die für die globale Anmeldung noch nicht voll ist (zweiter Faktor offen, Kette unvollständig), geht zuerst zu deren fehlendem Schritt — auch bei `factors=["password"]` (seit 2026-09-27; bis dahin überschrieb die Route-Kette die globale). Lief die Anmeldung über den Anmelde-Link und hat das Konto TOTP oder einen Passkey, verlangt auch eine Route-Kette ihn (`magiclink_require_second_factor`, wie in der globalen Policy).

### `require_admin(request: 'Request') -> 'dict'`

FastAPI-Dependency (direkt): eingeloggt + Admin (+ Step-up, wenn admin_require_mfa).

### `require_csrf(request: 'Request', submitted)`

Für Formular-POSTs: wirft 403, wenn der CSRF-Token fehlt/nicht passt.

### `require_mfa(request: 'Request') -> 'dict'`

FastAPI-Dependency (direkt): eingeloggt + frische Step-up-Bestätigung.

### `require_resource(name: 'str')`

FastAPI-Dependency-Factory: Bereich erst nach Eingabe des Ressourcen-Geheimnisses zugänglich. Unabhängig vom Benutzer-Login. `Depends(auth.require_resource('fotos'))`.

### `require_role(*roles, mfa: 'bool' = False, admin_implies: 'Optional[bool]' = None)`

FastAPI-Dependency-Factory: eingeloggt + Rolle. `Depends(auth.require_role('editor'))`.

### `require_session(request: 'Request', user: 'Optional[dict]' = None) -> 'dict'`

Eingeloggt — und zwar **interaktiv**: eine Sitzung ja, ein API-Key nein (403).

### `require_user(request: 'Request') -> 'dict'`

FastAPI-Dependency (direkt): erzwingt eingeloggten (inkl. MFA) User. Wer keine Rollen braucht: `Depends(auth.require_user)` genügt.

### `revoke_api_key(key_id, user_id=None)`

Einen Key entwerten. Er bleibt in der Liste stehen — wer ihn ausgestellt hat, soll das sehen.

### `rotate_session(request, response) -> 'Optional[str]'`

Der laufenden Sitzung ein neues Token geben und das Cookie setzen (F-06).

### `router()`

Der FastAPI-Router mit allen aktivierten Routen. Einmal einbinden, fertig.

### `safe_next(next_: 'str', request: 'Optional[Request]' = None) -> 'str'`

?next=-Ziel gegen Open-Redirect absichern (nur relative Pfade bzw. trusted_redirect_hosts).

### `send_login_link(email, base_url, next='/') -> 'bool'`

Login-Link an eine E-Mail schicken, WENN ein passender interaktiver User existiert. Rückgabe nur intern — nach außen immer dieselbe Meldung (keine User-Enumeration). `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

### `send_password_reset(email, base_url) -> 'bool'`

Reset-Link an eine E-Mail schicken, WENN ein passender User existiert. Nach außen immer gleiche Meldung (keine Enumeration). `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

### `send_verify_email(user_id, email, base_url) -> 'bool'`

Den Bestätigungslink für eine Adresse verschicken. False, wenn kein Mailer da ist. `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`). Scheitert der Versand, ist der Token entwertet (B6-12) und der Fehler geht weiter. Der Link schaltet ein mit `store.set_disabled(uid, True)` gesperrtes Konto frei (die ausstehende Bestätigung), nie eines, das der Betreiber gesperrt hat (Admin-Panel, `set_disabled(uid, True, durch_betreiber=True)`) — auch dann nicht, wenn der Link erst nach dieser Sperre entsteht, etwa weil der Aufruf über `nach_der_antwort` wartet (H-18). Eingelöst setzt er den Beleg für die Adresse (`email_verified`), solange sie noch die des Kontos ist.

### `set_cookie(response, token, remember: 'Optional[bool]' = None)`

Session-Cookie setzen. remember=True → persistentes Cookie (max_age = lange TTL); remember=False → reines Session-Cookie (max_age=None, endet beim Browser-Schließen).

### `set_mailer(fn)`

Eigenen Mail-Versand einhängen: fn(to, subject, text, html=None). Überschreibt SMTP.

### `set_owner(user_id: 'int', owner: 'bool') -> 'bool'`

Die Owner-Rolle vergeben (`owner=True`) oder abgeben (`False`). False = kein solches Konto.

### `set_password(user_id, password)`

Das Passwort eines Kontos setzen (ohne das alte zu prüfen — das ist Sache des Aufrufers).

### `set_pin(user_id, pin)`

PIN setzen/ändern. Mindestlänge aus cfg.pin_min_length.

### `set_resource_secret(name, secret, kind='pin', label=None)`

Geheimnis für einen Bereich setzen/ändern. kind='pin' (numerisch) \| 'password' (Passphrase).

### `set_security(key, value)`

Eine Härtungs-Schwelle zur Laufzeit setzen; sie überlebt den Neustart in der Datenbank.

### `set_template(name, fn)`

Eine eingebaute Seite durch einen eigenen Renderer ersetzen: fn(auth, ctx) -> str \| Response.

### `start_session(user_id, method, ip=None, ua=None, remember: 'bool' = True) -> 'tuple[str, bool]'`

Neue Session mit dem ersten Faktor. Gibt (token, session_ok). session_ok=False → weitere Schritte nötig.

### `stepup_options(user) -> 'list[str]'`

Womit kann DIESER User eine Step-up-Bestätigung leisten? Reihenfolge = Vorschlag.

### `totp_disable(user_id)`

TOTP entfernen, samt der Recovery-Codes (beides wird protokolliert).

## A · Eigenschaften von `TinySesam`

Ohne Klammern gelesen (`auth.csrf_cookie_name`). Zur Laufzeit berechnet: Sie folgen der Konfiguration, auch wenn `cfg` nach dem Aufbau geändert wird.

### `csrf_cookie_name` — Property `-> 'str'`

Der tatsächliche Name des CSRF-Cookies — eigenes JS bekommt ihn von der Seite.

### `resource_cookie_name` — Property `-> 'str'`

Der tatsächliche Name des Freigabe-Cookies der Bereichs-PIN.

### `session_cookie_name` — Property `-> 'str'`

Der tatsächliche Name des Sitzungs-Cookies (mit `__Host-`, wo möglich).

## A · Konstanten von `TinySesam`

Klassenattribute, gelesen als `TinySesam.NAME` oder `auth.NAME`. Der Wert gehört zur Zusage — der Wächter hält ihn fest.

### `FORWARD_HEADERS_DEFAULT` — Konstante

Vorgabe: der Satz, den Authelia/Traefik-Aufbauten erwarten.

Wert: `{'user': 'Remote-User', 'name': 'Remote-Name', 'email': 'Remote-Email', 'groups': 'Remote-Groups', 'id': 'Remote-Id'}`

### `SICHERHEITSEREIGNISSE` — Konstante

Die Ereignisse, zu denen `on_security_event` gerufen wird — alles, was einen Anmeldefaktor des Kontos anlegt, ändert, entfernt oder verbraucht.

Werte: `password_changed`, `pin_set`, `pin_disabled`, `totp_enabled`, `totp_disabled`, `recovery_codes_generated`, `recovery_code_used`, `passkey_added`, `passkey_removed`, `api_key_created`, `api_key_revoked`, `api_keys_revoked`, `email_changed`, `username_changed`

## A · `TinySesamConfig`

`TinySesamConfig` ist eine Dataclass und bleibt eine: `dataclasses.fields(TinySesamConfig)` zählt jedes Feld auf. Presets setzen Bündel dieser Felder, einzelne lassen sich per `**overrides` überschreiben.

### `TinySesamConfig.active_directory(ldap_url, upn_suffix=None, base_dn=None, bind_dn='', bind_password='', allowed_groups=None, **overrides)`

Preset: Passwort-Login gegen **Active Directory** (via LDAP). Entweder Direkt-Bind per UPN (`upn_suffix="corp.example.com"` → user@corp.example.com) ODER Search-then-Bind über sAMAccountName (`bind_dn`/`bind_password`/`base_dn`). Restliche Felder via **overrides (db_path …).

### `TinySesamConfig.entra_id(tenant_id, client_id, client_secret, oidc_name='Microsoft', **overrides)`

Preset: **Entra ID / Azure AD** via OIDC (Cloud-AD). tenant_id = Verzeichnis-(Tenant-)ID.

### `TinySesamConfig.local_accounts(**overrides)`

Preset: **nur Benutzername + Passwort**, ganz ohne E-Mail.

### `TinySesamConfig.oidc_gateway(issuer, client_id, client_secret, base_url, cookie_domain='', trusted_redirect_hosts=None, allowed_groups=None, group_claim='groups', oidc_name='SSO', oidc_scopes='openid profile email', db_path='tinysesam-gateway.db', https_mode='warn', session_ttl_hours=168, trusted_proxies=None, clients=None, revalidate_minutes=60, **overrides)`

Preset: TinySesam als reines **OIDC-Forward-Auth-Gateway** (Authelia-/oauth2-proxy-Stil). Alle anderen Methoden/Features aus, OIDC + Forward-Auth an. Läuft mit `pip install 'tinysesam[oidc]'`. Einzelne Felder via **overrides überschreibbar.

## A · Fehlertypen

Exportiert aus `tinysesam`. Jeder erbt zusätzlich von dem eingebauten Typ, den er ersetzt — bestehendes `except ValueError` / `except RuntimeError` fängt weiter, es wird nur unterscheidbar. **Auf den Meldungstext prüft niemand:** er ist übersetzt und darf sich ändern; die Typen hier und die Attribute an ihnen sind die Zusage.

### `TinySesamError` (erbt von `Exception`)

Basis aller eigenen Fehler — `except TinySesamError` fängt alles von hier.

### `ConfigError` (erbt von `TinySesamError`, `ValueError`)

Die Konfiguration widerspricht sich oder verspricht etwas, das so nicht wirkt.

### `MailNotConfigured` (erbt von `TinySesamError`, `RuntimeError`)

Es sollte eine Mail raus, aber kein Mailer ist eingerichtet.

### `MissingExtra` (erbt von `TinySesamError`, `RuntimeError`)

Ein aktivierter Schalter braucht ein Extra, das nicht installiert ist.

### `StateError` (erbt von `TinySesamError`, `RuntimeError`)

Der Vorgang passt nicht zum Zustand des Kontos — und wird deshalb verweigert.

## A · Ergebnis der Anmelde-Bausteine: `tinysesam.Anmeldung`

Was ein Anmeldeschritt ergeben hat: Erfolg oder der Grund dagegen, mit HTTP-Status und Text. Zurück von `anmelden_passwort`, `anmelden_pin`, `anmelden_totp`. Eine eingefrorene Dataclass; `bool(erg)` ist `erg.ok`. Das Sitzungs-Token ist bewusst kein Feld — `cookie_setzen()` und `weiterleitung()` setzen es.

| Feld | Typ | Bedeutung |
|---|---|---|
| `ok` | `bool` | Hat der Schritt angemeldet? Genau dann, wenn `grund == "ok"`; `bool(erg)` ist derselbe Wert. |
| `grund` | `str` | Warum (nicht): einer der Werte aus `GRUENDE`. Für Programme — der Text steht in `meldung`. |
| `status` | `int` | Der HTTP-Status der eingebauten Seite: 303 bei Erfolg, sonst 400, 401, 404, 429 oder 503. |
| `meldung` | `str` | Der übersetzte Text für den Nutzer (Sprache aus `config.lang`); leer bei Erfolg. |
| `weiter` | `str` | Das geprüfte Ziel (`safe_next`, mit Montage-Präfix): bei Erfolg der nächste Faktor-Schritt oder `next`, sonst `next` fürs Formular — bei `keine_sitzung` die Login-Seite. |
| `naechster` | `Optional[str]` | Der offene Faktor nach diesem Schritt (etwa `"totp"`), für eine eigene Seite des nächsten Schritts. Bei einem Fehlschlag im Folgeschritt derselbe Faktor noch einmal, sonst None. |
| `fertig` | `bool` | Ist die Sitzung vollständig angemeldet? Nur bei Erfolg und ohne offenen Faktor True. |
| `user` | `Optional[dict]` | Das angemeldete Konto (wie `get_user`) — nur bei Erfolg, sonst None. |

### `Anmeldung.GRUENDE` — Konstante

Jeder Wert, den `grund` annehmen kann.

Wert: `('ok', 'leer', 'falsch', 'gesperrt', 'gesperrt_serie', 'ratelimit', 'verzeichnis_weg', 'abgeschaltet', 'keine_sitzung')`

### `Anmeldung.cookie_setzen(response) -> 'None'`

Das Sitzungs-Cookie in `response` setzen, falls der Schritt ein neues Token ergeben hat.

### `Anmeldung.weiterleitung()`

Eine Umleitung (303) nach `weiter`, mit gesetztem Sitzungs-Cookie, falls es eines gibt.

## A · weitere Exporte von `tinysesam`

- `TinySesam`
- `TinySesamConfig`

## B · Methoden von `TinySesam`

### `admin_claim_token() -> 'Optional[str]'`

Weg 2: Einmal-Token. Solange kein Admin existiert, gibt es ein Token, das genau einmal eingelöst werden kann (`/auth/claim-admin?token=…`). Der Wert geht beim Start auf stderr bzw. in `admin_claim_token_file` (0600) — wer den Server betreibt, hat ihn; wer bloß die URL kennt oder das Log lesen kann, nicht (B5-03). Läuft ab.

### `admin_exists() -> 'bool'`

Gibt es mindestens einen Admin? Die beiden Bootstrap-Wege greifen nur, solange nicht.

### `all_security() -> 'dict'`

Alle Härtungs-Schwellen als Dict (Vorgaben, überschrieben von dem, was im Panel steht).

### `andere_sitzungen(request, user, token: 'Optional[str]' = None) -> 'int'`

Wie viele Sitzungen dieses Kontos laufen AUSSER der aktuellen? (B1-7)

### `api_key_art(key) -> 'str'`

Die Art eines Keys ("automat"/"mensch") — ohne ihn zu benutzen.

### `apply_factor(request, user_id, factor, ip=None, ua=None, remember=True, email_bestaetigt: 'Optional[bool]' = None) -> 'tuple[str, bool, bool]'`

Einen bestätigten Faktor anwenden: an die laufende Sitzung desselben Users anhängen (Ketten-Schritt) ODER eine neue Sitzung starten (Erstfaktor/Identitätswechsel). Gibt (token, session_ok, is_new). Bei is_new muss der Aufrufer set_cookie(resp, token) rufen.

### `apply_idp_groups(user_id, groups, mapping: 'dict', substring: 'Optional[bool]' = None, dn: 'bool' = False)`

IdP-Gruppen → lokale Rollen (beim Login). Gemappte Rollen werden synchronisiert (bei Wegfall der Gruppe entfernt), manuell vergebene Rollen bleiben. Ziel '__admin__' setzt das Admin-Flag und nimmt es wieder, wenn es vom Provider stammt (H-5).

### `audit(event, username=None, ip=None, detail=None)`

Einen Vorgang ins Audit-Log schreiben. `detail` nimmt alles, was später die Frage „warum" beantwortet.

### `client_ip(request: 'Request') -> 'str'`

Die echte Client-IP. Hinter einem Proxy nur dann aus `X-Forwarded-For`, wenn der Peer in `trusted_proxies` steht — sonst wäre der Header fälschbar.

### `confirm_email_change(raw, ip: 'Optional[str]' = None) -> 'Optional[str]'`

Den Bestätigungslink einlösen. Rückgabe: "ok", "vergeben" (inzwischen Kennung eines anderen Kontos) oder None (ungültig, abgelaufen, benutzt, Konto gesperrt/weg).

### `create_magic_token(purpose, user_id=None, email=None, ttl_min=None, payload=None) -> 'str'`

Einmal-Token erzeugen (Klartext-Rückgabe). Nur der sha256-Hash liegt in der DB.

### `darf_mfa_einrichten(user_id: 'int', jetzt: 'Optional[int]' = None) -> 'bool'`

Darf dieses Konto den von der Kette verlangten Faktor **selbst** einrichten? (R3-1)

### `delete_user(user_id: 'int') -> 'bool'`

Ein Konto samt aller Zugangsdaten löschen (B5-08) — und es aus dem Audit-Log nehmen (H-13).

### `disable_pin(user_id)`

Die PIN eines Kontos entfernen (wird protokolliert — ein zweiter Faktor verschwindet nicht unbemerkt).

### `find_user(identifier) -> 'Optional[dict]'`

Konto zur Login-Kennung suchen — je nach `config.login_identifier`.

### `flow_cookie_name(basis: 'str') -> 'str'`

Name eines Flow-Cookies (OIDC, SAML, Passkey) — mit `__Host-`, wo möglich (A-1).

### `generate_recovery_codes(user_id, n=None) -> 'list'`

Neue Einmal-Codes erzeugen (ersetzt vorhandene). Klartext-Rückgabe NUR EINMAL.

### `get_user(user_id) -> 'Optional[dict]'`

Ein Konto per ID lesen, oder None.

### `has_pin(user_id) -> 'bool'`

Hat dieses Konto eine PIN eingerichtet?

### `json_body(request: 'Request') -> 'dict'`

JSON-Body robust lesen: ungültiger/leerer Body → 400 statt 500. Erzwingt CSRF (Header X-CSRF-Token) für cookie-basierte Clients; API-Key-Requests sind ausgenommen.

### `kennung_vergeben(kennung, exclude_id=None) -> 'Optional[dict]'`

Gehört diese Login-Kennung schon einem Konto — in IRGENDEINEM der beiden Namensräume?

### `list_api_keys(user_id)`

Die API-Keys eines Kontos — ohne die Schlüssel selbst, die gibt es nur einmal bei der Ausgabe.

### `list_resource_secrets()`

Alle gesperrten Ressourcen (Namen und Beschreibungen, keine Geheimnisse).

### `magic_url(raw, base_url, purpose='login') -> 'str'`

Der Link, den der Empfänger anklickt — Pfad je nach Zweck (`TOKEN_PATHS`). `base_url` wird geprüft: ein fremder Host wirft `ConfigError` — in einer Route liefert `public_base(request)` die geprüfte Basis.

### `mail_configured() -> 'bool'`

Kann überhaupt eine Mail hinausgehen — per SMTP oder per `set_mailer`?

### `nach_der_antwort(resp, auftrag, bei_ueberlauf=None)`

`auftrag()` erst NACH dem Versand der Antwort ausführen, im eigenen Mail-Arbeiter (`mailer.Postausgang`, R4-05/B6-6). Gibt `resp` zurück.

### `nur_foederiert(user_id) -> 'bool'`

Reines SSO-Konto: an einen IdP/ein Verzeichnis gebunden und ohne lokales Passwort.

### `own_events(user_id: 'int', limit: 'int' = 20) -> 'list'`

Die jüngsten Audit-Ereignisse eines Kontos, für die Kontoseite (H-7).

### `passwort_mangel(password, username=None, email=None, api: 'bool' = False) -> 'Optional[str]'`

Die Passwortregel für ein NEUES Passwort — `None` heisst „in Ordnung", sonst der übersetzte Grund (`api=True`: der Text für eine JSON-Antwort).

### `peek_magic(raw, purpose=None) -> 'Optional[dict]'`

Token prüfen OHNE ihn zu verbrauchen (für den Invite-Flow: erst bei Registrierung einlösen).

### `pending_user(request) -> 'Optional[dict]'`

User einer Session, die noch im MFA-Schritt hängt (mfa_ok=0).

### `pfad(request: 'Optional[Request]', pfad: 'str') -> 'str'`

Einen Pfad der App (`/auth/login`, `login_path`, `admin_path`, …) in den Pfad umrechnen, den der Browser braucht — mit dem Montage-Präfix davor (T-15).

### `recovery_codes_remaining(user_id) -> 'int'`

Wie viele Einmal-Codes dieses Konto noch hat.

### `redeem_magic(raw, purpose=None) -> 'Optional[dict]'`

Token einlösen (one-shot). Gibt {purpose,user_id,email,payload} oder None (ungültig/abgelaufen/benutzt).

### `remove_passkey(user_id: 'int', passkey_id: 'int', ip: 'Optional[str]' = None) -> 'bool'`

Einen Passkey eines Kontos entfernen — Löschen, Audit-Zeile und `passkey_removed` in einem.

### `remove_resource_secret(name)`

Eine gesperrte Ressource wieder freigeben (die Sperre entfernen, nicht entsperren).

### `request_email_change(user_id, neu, base_url)`

Den Wechsel auf eine neue Adresse beantragen: Bestätigungslink an die NEUE. Gibt die Versandfunktion zurück (für `nach_der_antwort`) — auch dann, wenn die Adresse vergeben oder reserviert ist und kein Link hinausgeht; `senden()` sagt es mit True/False. None nur bei einer Drossel und für die eigene, schon belegte Adresse. `ValueError` bei einer ungültigen Adresse oder ohne Mailer. Fällt der Versand aus, bevor er beginnt (volle Warteschlange), lässt `senden.verwerfen()` den Token verfallen — als `bei_ueberlauf` für `nach_der_antwort` (seit 2026-09-27).

### `require_public_base(request: 'Optional[Request]' = None, kandidat: 'str' = '') -> 'str'`

Wie `public_base()`, nur ohne Rückweg: keine geprüfte Basis → `ConfigError`.

### `resource_unlocked(request: 'Request', name) -> 'bool'`

Ist diese Ressource für diesen Browser gerade freigeschaltet?

### `revoke_mfa_enrollment(user_id: 'int') -> 'None'`

Ein offenes Einrichtungsfenster sofort schliessen.

### `send_mail(to, subject, text, html=None)`

Eine Mail versenden — über SMTP oder den per `set_mailer` gesetzten Weg.

### `session_user(request) -> 'Optional[dict]'`

Das Konto der vollen Sitzung dieses Requests — wie `current_user()`, nur nie aus einem API-Key.

### `set_rate_limiter(limiter)`

Eigenes Rate-Limit-Backend einhängen — beliebiges Objekt mit allow(key, max, window)->bool.

### `set_roles(user_id, roles)`

Die Rollen eines Kontos ersetzen.

### `sperre_aufheben(user_id, methoden=None) -> 'int'`

Die Anmelde-Fehlversuche eines Kontos wegräumen; gibt zurück, wie viele es waren.

### `stepup_fresh(request: 'Request', user: 'Optional[dict]' = None) -> 'bool'`

True, wenn die aktuelle Sitzung frisch einen Faktor bestätigt hat (Sudo-Frische).

### `t(key, **fmt) -> 'str'`

Übersetzten Text für key in config.lang (Fallback en → key). Platzhalter via {name}.

### `totp_begin(user_id)`

Die Einrichtung starten: liefert Geheimnis und `otpauth://`-Adresse für den Authenticator — und wirft neu `StateError` (kein `ConfigError`, kein stiller Erfolg), wenn das Konto bereits ein bestätigtes TOTP hat.

### `totp_confirm(user_id, code) -> 'bool'`

Die Einrichtung abschliessen — erst mit einem gültigen Code ist TOTP wirklich an.

### `totp_enrollment_user(request) -> 'Optional[dict]'`

Wer darf TOTP einrichten, **ohne** schon voll angemeldet zu sein? Sonst None.

### `user_roles(user) -> 'list'`

Die Rollen eines Kontos als Liste.

### `verify_api_key(key)`

(user, key_roles\|None) bei gültigem Key, sonst (None, None).

### `version() -> 'str'`

Die laufende Version — fürs Panel. TinySesam aktualisiert sich nicht selbst; das erledigt, wer es installiert hat (gepinnter Tag / Wheel eines Releases).

## B · Konstanten von `TinySesam`

Klassenattribute, gelesen als `TinySesam.NAME` oder `auth.NAME`. Der Wert gehört zur Zusage — der Wächter hält ihn fest.

### `FOEDERIERTE_QUELLEN` — Konstante

Quellen, die eine fremde Identität über eine stabile Kennung binden (F-11).

Wert: `('ldap', 'saml')`

### `MFA_ENROLLMENT_ARTEN` — Konstante

Die erlaubten Werte von `cfg.mfa_enrollment` — als Liste, damit ein Tippfehler beim Aufbau auffällt und nicht erst dann, wenn jemand vor der Tür steht.

Wert: `('first_login', 'grace', 'strict')`

### `NACHBINDUNG_GRUENDE` — Konstante

Warum ein Konto nicht über den Namen gebunden wird (`_nachbindung_grund`) — für Log und Bericht.

Schlüssel: `adresse_als_name`, `kennung_ungueltig`, `konflikt`, `anders_gebunden`, `name_selbst_gewaehlt`, `name_aus_quelle`, `frist`

### `NAME_MAX` — Konstante

Länger ist kein Name mehr, sondern eine Nutzlast (Header, Logzeilen, Panel).

Wert: `150`

### `SEITEN` — Konstante

Die Seiten, die sich ersetzen lassen — dieselbe Liste, die `render_page()` bedient.

Wert: `('account', 'error', 'forgot', 'login', 'logout', 'magic_confirm', 'magic_invalid', 'magic_request', 'pin', 'reauth', 'register', 'reset', 'resource_unlock', 'totp', 'totp_setup')`

### `TOKEN_PATHS` — Konstante

Wo ein Token eingelöst wird — je Zweck ein eigener Endpunkt.

Wert: `{'login': '/auth/magic/{t}', 'verify_email': '/auth/verify/{t}', 'invite': '/auth/invite/{t}', 'reset_password': '/auth/reset?token={t}', 'email_change': '/auth/email/{t}'}`

## B · `TinySesamConfig`

Felder dieser Stufe (Bedeutung in [KONFIGURATION.md](KONFIGURATION.md)): `totp_required`.

### `TinySesamConfig.enabled_methods() -> 'list[str]'`

Erstfaktoren, die die Login-Seite anbietet. Eine PIN, die kein Erstfaktor sein kann (`pin_als_erstfaktor()`), steht hier bewusst NICHT — sie bleibt als Zusatzfaktor/Step-up nutzbar.

### `TinySesamConfig.pin_als_erstfaktor() -> 'bool'`

Meldet eine PIN als ERSTER Faktor an — auf der Login-Seite und über `/auth/pin` ohne Sitzung?

### `TinySesamConfig.pruefen() -> 'list[str]'`

Die Konfiguration erneut prüfen — für den Fall, dass sie nach dem Aufbau geändert wurde.

## B · weitere Exporte von `tinysesam`

### `tinysesam.current_version() -> str`

Installierte Version — bevorzugt die Distribution-Metadaten, die auch dann stimmen, wenn TinySesam als Abhängigkeit in einer fremden App steckt.

## C · Veraltet — fällt mit 1.0 weg

Diese Namen gehören nicht zur Zusage. Seit 0.22.0 heisst die Implementierung `_name`; der alte Name bleibt bis 1.0 als Alias, der **beim Aufruf** (Konstanten: beim Lesen) eine `DeprecationWarning` mit dem Ersatz auslöst, und fällt dann weg. **Neu nicht verwenden** — für eigene Seiten stehen die Bausteine in A und B. Wer prüfen will, ob seine App einen davon ruft, lässt ihre Tests einmal mit `python -W error::DeprecationWarning` laufen.

**Vorsicht bei den inneren Prüfern** `check_password`, `check_pin`, `check_ldap`, `check_saml`: Sie drosseln nicht selbst — Sperre, Fehlversuchszähler und Serie setzen nur die eingebauten Routen. Eine eigene Login-Seite, die sie aufruft, ist gegen Passwort-Raten ungeschützt. Der sichere Baustein ist `anmelden_passwort`, `anmelden_pin`, `anmelden_totp` (Stufe A): dieselben Methoden, die die eingebauten Routen rufen.

| Alter Name | Art | Ersatz |
|---|---|---|
| `admin_claim_fehlgriff` | Methode | Ohne Ersatz; die Route `/auth/claim-admin` protokolliert selbst |
| `APIKEY_AUDIT_FENSTER` | Konstante | Ohne Ersatz, ein interner Wert |
| `check_ldap` | Methode | `anmelden_passwort` (fragt das Verzeichnis als Rückfall, drosselt und sperrt wie `POST /auth/login`) |
| `check_password` | Methode | `anmelden_passwort` (drosselt, zählt und sperrt wie `POST /auth/login`), für ein eigenes Aussehen allein `set_template("login", …)`; `check_password` selbst drosselt nicht |
| `check_pin` | Methode | `anmelden_pin` (drosselt, zählt und sperrt wie `POST /auth/pin`), für ein eigenes Aussehen allein `set_template("pin", …)`; `check_pin` selbst drosselt nicht |
| `check_resource` | Methode | `POST /auth/resource/{name}` (drosselt und sperrt) bzw. `require_resource` |
| `check_saml` | Methode | `POST /auth/saml/acs`, das die Signatur der Assertion prüft; `check_saml` vertraut seinen Argumenten |
| `complete_mfa` | Methode | `complete_totp` (gleiches Verhalten) |
| `consume_admin_claim` | Methode | Die Route `/auth/claim-admin`, `ensure_admin` oder `admin_identifiers` |
| `csrf_rotieren` | Methode | `set_cookie` (dreht das CSRF-Token bei der Anmeldung mit) bzw. `issue_csrf` |
| `DEMO_USERS` | Konstante | Ohne Ersatz; die Demo-Konten heissen `demo` und `demoadmin` (README) |
| `factor_entry` | Methode | Ohne Ersatz; `require_user`/`require` leiten selbst zum offenen Faktor |
| `FOEDERIERTE_FAKTOREN` | Konstante | Ohne Ersatz, eine innere Entscheidungsliste für den Erst-Admin |
| `forward_login_url` | Methode | Ohne Ersatz; die Route `/auth/forward` baut die Login-Adresse selbst |
| `forward_response_headers` | Methode | Ohne Ersatz; welche Header `/auth/forward` setzt, steuert `forward_headers` |
| `forwarded_url` | Methode | Ohne Ersatz; die Route `/auth/forward` liest die Proxy-Header selbst |
| `IDENTIFYING` | Konstante | Ohne Ersatz; welche Faktoren identifizieren, steht in docs/BETRIEB.md |
| `is_locked` | Methode | `anmelden_passwort`, `anmelden_pin` bzw. `anmelden_totp`, die atomar prüfen und buchen; `is_locked` liest nur und lässt parallele Salven durch |
| `is_password_change_locked` | Methode | `POST /auth/password` (prüft und bucht atomar) |
| `is_pin_locked` | Methode | `anmelden_pin` (prüft und bucht atomar wie `POST /auth/pin`) |
| `is_reauth_locked` | Methode | `/auth/reauth` (prüft und bucht atomar; `require(mfa=True)` leitet dorthin) |
| `is_resource_locked` | Methode | `POST /auth/resource/{name}` (prüft und bucht atomar) |
| `is_secure` | Methode | Ohne Ersatz; die Warnung ohne HTTPS steuert `https_mode` |
| `is_totp_setup_locked` | Methode | `POST /auth/totp/setup` (prüft und bucht atomar) |
| `login_redirect_after` | Methode | `weiter` bzw. `weiterleitung()` am Ergebnis von `anmelden_passwort`, `anmelden_pin` oder `anmelden_totp` (nächster Faktor oder `next`) |
| `maybe_promote_admin` | Methode | `admin_identifiers` oder `ensure_admin`; direkt gerufen umgeht es den Adressbeleg |
| `mfa_pending` | Methode | Ohne Ersatz (der Name meint „hat ein bestätigtes TOTP“); dasselbe liefert `auth.store.has_confirmed_totp(user_id)` |
| `next_login_step` | Methode | Ohne Ersatz; `require_user`/`require` leiten selbst zum offenen Faktor |
| `oidc_anwendung` | Methode | Ohne Ersatz; die Zuordnung steht in `oidc_clients` |
| `oidc_freigabe_gueltig` | Methode | Ohne Ersatz; die Zuordnung steht in `oidc_clients` |
| `purge_demo` | Methode | `demo_mode=False` (räumt die Demo-Konten beim Start) |
| `rate_ok` | Methode | `anmelden_passwort`, `anmelden_pin` bzw. `anmelden_totp` (drosseln je IP), ein eigener Limiter per `set_rate_limiter` |
| `record_login` | Methode | `anmelden_passwort`, `anmelden_pin` bzw. `anmelden_totp`, die jeden Versuch verbuchen; falsch gerufen räumt es fremde Fehlversuchszähler |
| `RECOVERY_BYTES` | Konstante | Ohne Ersatz, ein interner Wert |
| `RECOVERY_WARNSCHWELLE` | Konstante | `recovery_codes_remaining` und eine eigene Schwelle |
| `sec` | Methode | `all_security()` |
| `seed_demo` | Methode | `demo_mode=True` (legt die Demo-Konten beim Start an) |
| `send_signup_notice` | Methode | Ohne Ersatz; `POST /auth/register` verschickt den Hinweis selbst |
| `SERIE_PIN_FOLGE` | Konstante | `anmelden_pin` (bucht eine PIN hinter einem erbrachten Faktor selbst unter dieser Serien-Art) |
| `session_from_request` | Methode | `current_user` bzw. `session_user` |
| `sicherheitsereignis` | Methode | Ohne Ersatz; TinySesam ruft den Hook `on_security_event` selbst |
| `token_abgewiesen` | Methode | Ohne Ersatz; die eingebauten Token-Routen protokollieren selbst |
| `unlock_resource` | Methode | `POST /auth/resource/{name}` (prüft das Geheimnis vorher) |
| `verify_csrf` | Methode | `require_csrf` |
| `verify_recovery_code` | Methode | `anmelden_totp` (nimmt auch Einmal-Codes, drosselt und sperrt wie `POST /auth/totp`); `verify_recovery_code` selbst drosselt nicht |
| `verify_totp` | Methode | `anmelden_totp` (drosselt und sperrt wie `POST /auth/totp`); `verify_totp` selbst drosselt nicht |
| `verify_user_password` | Methode | `/auth/reauth` (`require(mfa=True)` leitet dorthin) bzw. `POST /auth/password`; ungedrosselt |
| `verify_user_pin` | Methode | `/auth/reauth` (`require(mfa=True)` leitet dorthin); ungedrosselt |
| `vermerke_oidc_freigabe` | Methode | Ohne Ersatz; die Zuordnung steht in `oidc_clients` |
| `versuch_beginnen` | Methode | `anmelden_passwort`, `anmelden_pin` bzw. `anmelden_totp`, die jeden Versuch atomar vorbuchen |

---

150 Methoden, 3 Eigenschaften, 15 Konstanten, 7 Methoden von `TinySesamConfig`, 9 Exporte, davon 5 Fehlertypen, 11 Namen an `Anmeldung` — erzeugt aus den Docstrings und `tests/api_surface.json`.
