# API — die öffentliche Oberfläche von `TinySesam`

<!-- GENERIERT von scripts/_api_doku.py — nicht von Hand pflegen.
     Neu bauen: `python3 scripts/_api_doku.py` -->

Diese Namen hält `tests/api_surface.json` fest: Was hier steht, ändert sich nicht ohne eine
bewusste Entscheidung und einen Eintrag im CHANGELOG.

Die READMEs zeigen die **Wege** (welche Methode wofür, wie man sie kombiniert). Hier steht, was
es überhaupt gibt — die Frage „gibt es dafür schon etwas?" beantwortet diese Seite, nicht der
Quelltext.

> **Gemessen, nicht ausgewählt.** Erfasst ist alles ohne führenden Unterstrich. Welche dieser
> Methoden auf Dauer öffentlich sein *sollen*, ist eine offene Entscheidung für 1.0
> ([M-1](backlog/M-1-api-stabil-1-0.md)) — bis dahin gilt: eingefroren ist, was hier steht.

Die Konfigurationsfelder stehen in [KONFIGURATION.md](KONFIGURATION.md).

## `TinySesam`

### `add_messages(lang, mapping: 'dict')`

Eigene Übersetzungen ergänzen/überschreiben (haben Vorrang vor den eingebauten).

### `admin_claim_fehlgriff(username, ip) -> 'None'`

Einen gescheiterten Erst-Admin-Claim festhalten — Audit-Log und Sicherheits-Log (B5-16).

### `admin_claim_token() -> 'Optional[str]'`

Weg 2: Einmal-Token. Solange kein Admin existiert, gibt es ein Token, das genau einmal eingelöst werden kann (`/auth/claim-admin?token=…`). Der Wert geht beim Start auf stderr bzw. in `admin_claim_token_file` (0600) — wer den Server betreibt, hat ihn; wer bloß die URL kennt oder das Log lesen kann, nicht (B5-03). Läuft ab.

### `admin_exists() -> 'bool'`

Gibt es mindestens einen Admin? Die beiden Bootstrap-Wege greifen nur, solange nicht.

### `admin_router()`

Eigenständiger Admin-Router (relative Pfade) — an beliebigem Prefix / Sub-App / Port montierbar, oder (admin_ui_enabled=False) nur die JSON-API fürs eigene Panel.

### `all_security() -> 'dict'`

Alle Härtungs-Schwellen als Dict (Vorgaben, überschrieben von dem, was im Panel steht).

### `andere_sitzungen(request, user, token: 'Optional[str]' = None) -> 'int'`

Wie viele Sitzungen dieses Kontos laufen AUSSER der aktuellen? (B1-7)

### `api_key_art(key) -> 'str'`

Die Art eines Keys ("automat"/"mensch") — ohne ihn zu benutzen.

### `apply_factor(request, user_id, factor, ip=None, ua=None, remember=True, email_bestaetigt: 'Optional[bool]' = None) -> 'tuple[str, bool, bool]'`

Einen bestätigten Faktor anwenden: an die laufende Sitzung desselben Users anhängen (Ketten-Schritt) ODER eine neue Sitzung starten (Erstfaktor/Identitätswechsel). Gibt (token, session_ok, is_new). Bei is_new muss der Aufrufer set_cookie(resp, token) rufen.

### `apply_idp_groups(user_id, groups, mapping: 'dict', substring: 'Optional[bool]' = None, dn: 'bool' = False)`

IdP-Gruppen → lokale Rollen (beim Login). Ziel '__admin__' setzt das Admin-Flag (nur grant, nie automatisch entziehen). Gemappte Rollen werden synchronisiert (bei Wegfall der Gruppe entfernt), manuell vergebene Rollen bleiben.

### `audit(event, username=None, ip=None, detail=None)`

Einen Vorgang ins Audit-Log schreiben. `detail` nimmt alles, was später die Frage „warum" beantwortet.

### `check_ldap(username, password) -> 'Optional[dict]'`

Passwort gegen LDAP prüfen. Bei Erfolg lokalen User finden/anlegen und zurückgeben. Zählt wie ein Passwort-Login (Faktor 'password').

### `check_password(username, password) -> 'Optional[dict]'`

Benutzername/E-Mail + Passwort prüfen. Gibt das Konto zurück oder None — und braucht bei beiden Ausgängen gleich lange (keine Konto-Erkundung).

### `check_pin(username, pin) -> 'Optional[dict]'`

Wie `check_password`, nur mit der persönlichen PIN.

### `check_resource(name, secret) -> 'bool'`

Das Geheimnis einer gesperrten Ressource prüfen (ohne sie freizuschalten — das tut `unlock_resource`).

### `check_saml(nameid, attrs, ip: 'Optional[str]' = None) -> 'Optional[dict]'`

Aus einer geprüften SAML-Assertion einen lokalen User finden/anlegen. Faktor 'saml'.

### `client_ip(request: 'Request') -> 'str'`

Die echte Client-IP. Hinter einem Proxy nur dann aus `X-Forwarded-For`, wenn der Peer in `trusted_proxies` steht — sonst wäre der Header fälschbar.

### `complete_mfa(token)`

Historischer Name für `complete_totp()` — bleibt erhalten, damit nichts bricht.

### `complete_totp(token) -> 'Optional[str]'`

Den TOTP-Schritt abschließen: Faktor `totp` an die laufende Sitzung anhängen.

### `consume_admin_claim(token, user) -> 'bool'`

Das Einmal-Token einlösen und dieses Konto zum Admin machen. Gilt genau einmal.

### `create_api_key(user_id, name=None, expires_days=None, roles=None, kind: 'str' = 'automat') -> 'dict'`

Neuen API-Key erzeugen. Rückgabe enthält 'key' im KLARTEXT — nur EINMAL (danach nur der Hash).

### `create_invite(email, base_url, roles=None, is_admin=False, ttl_min=None) -> 'dict'`

Einladung erzeugen (+ optional versenden). Rückgabe {url, token}. Der Token trägt die vorgesehenen Rollen/Adminrechte; eingelöst wird er erst bei der Registrierung. `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

### `create_magic_token(purpose, user_id=None, email=None, ttl_min=None, payload=None) -> 'str'`

Einmal-Token erzeugen (Klartext-Rückgabe). Nur der sha256-Hash liegt in der DB.

### `create_service(username, roles=None, display_name=None) -> 'int'`

Service-/Daemon-Account: kein interaktiver Login, nur API-Keys. Rollen = Rechte-Scope.

### `create_user(username, password=None, is_admin=False, roles=None, display_name=None, email=None, is_service=False, email_verified: 'bool' = True) -> 'int'`

Ein Konto anlegen und seine ID zurückgeben. `is_service=True` für Maschinen: kein Login, nur API-Keys. Eine bereits vergebene Kennung wirft `ConfigError` — **neu auch beim doppelten Benutzernamen**, der bis 0.18.x als `sqlite3.IntegrityError` aus der Datenbank kam (`e.feld`/`e.besitzer_id` sagen, was kollidierte).

### `csrf_rotieren(response) -> 'str'`

Ein frisches CSRF-Token setzen — beim Login.

### `csrf_token(request: 'Optional[Request]' = None) -> 'str'`

Das CSRF-Token dieses Browsers — vorhandenes Cookie wiederverwenden, sonst neu würfeln.

### `current_user(request) -> 'Optional[dict]'`

Das angemeldete Konto zu diesem Request — aus der Sitzung ODER einem API-Key. None, wenn niemand angemeldet ist.

### `darf_mfa_einrichten(user_id: 'int', jetzt: 'Optional[int]' = None) -> 'bool'`

Darf dieses Konto den von der Kette verlangten Faktor **selbst** einrichten? (R3-1)

### `delete_user(user_id: 'int') -> 'bool'`

Ein Konto samt aller Zugangsdaten löschen (B5-08) — und es aus dem Audit-Log nehmen (H-13).

### `disable_pin(user_id)`

Die PIN eines Kontos entfernen (wird protokolliert — ein zweiter Faktor verschwindet nicht unbemerkt).

### `ensure_admin(username, password) -> 'bool'`

Bootstrap: legt einen Admin an, WENN noch kein User existiert. True bei Anlage.

### `factor_entry(step, nxt='/') -> 'str'`

Die Adresse der Eingabeseite für einen Faktor-Schritt, mit `next` daran.

### `find_user(identifier) -> 'Optional[dict]'`

Konto zur Login-Kennung suchen — je nach `config.login_identifier`.

### `flow_cookie_name(basis: 'str') -> 'str'`

Name eines Flow-Cookies (OIDC, SAML, Passkey) — mit `__Host-`, wo möglich (A-1).

### `forward_login_url(orig_url: 'str', request: 'Optional[Request]' = None) -> 'str'`

Zentrale Login-URL (auf base_url bzw. abgeleitet) mit next=<orig_url>.

### `forward_response_headers(user) -> 'dict'`

Die Header, die der Proxy bei einer erfolgreichen Prüfung an die App weiterreicht.

### `forwarded_url(request: 'Request') -> 'str'`

Ursprüngliche vom Proxy angefragte URL rekonstruieren (Caddy/Traefik: X-Forwarded-*, nginx: X-Original-URL). Fallback: Referer bzw. '/'.

### `gc(attempts_older_than_sec: 'int' = 86400) -> 'dict'`

Aufräumen: abgelaufene Sessions/Flows/Magic-Tokens/Ressourcen-Unlocks + alte Login-Versuche. Regelmäßig aufrufen (Cron/Startup/Scheduler) — sonst wachsen die Tabellen. Das Audit-Log nur, wenn `audit_retention_days` eine Frist setzt (B5-11) — dann steht die Zahl unter `audit`. Gibt Anzahl gelöschter Zeilen je Bereich.

### `generate_recovery_codes(user_id, n=None) -> 'list'`

Neue Einmal-Codes erzeugen (ersetzt vorhandene). Klartext-Rückgabe NUR EINMAL.

### `get_user(user_id) -> 'Optional[dict]'`

Ein Konto per ID lesen, oder None.

### `grant_mfa_enrollment(user_id: 'int', minutes: 'int' = 60) -> 'int'`

Ein Einrichtungsfenster öffnen und seinen Ablauf zurückgeben.

### `has_pin(user_id) -> 'bool'`

Hat dieses Konto eine PIN eingerichtet?

### `has_role(user, role, admin_implies=None) -> 'bool'`

Hat der User die Rolle? Ein Admin erfüllt standardmäßig JEDE Rolle (`config.admin_implies_roles`). Wer Rechte allein an IdP-Gruppen hängt, schaltet das ab — sonst ist jeder lokale Admin automatisch auch „editor", „viewer", … .

### `install_error_pages(app)`

Themed Fehlerseiten registrieren (opt-in). Browser bekommen die 'error'-Seite (im Branding), API-Clients JSON; Redirects (Login/Reauth/Faktor, via Location-Header) bleiben Redirects.

### `install_https(app)`

HTTPS gemäß config.https_mode: 'force' → HTTP→HTTPS-Redirect-Middleware; 'warn'/'off' → läuft auch OHNE Zertifikat (bei 'warn' Panel-Hinweis). Gibt den Modus zurück.

### `is_admin(user) -> 'bool'`

Ist dieses Konto Admin? Nimmt eine Kontozeile, kein Request.

### `is_locked(username, ip) -> 'bool'`

Zu viele Fehlversuche im Fenster — je Paar aus Konto und IP, je Konto, je IP.

### `is_password_change_locked(username, ip) -> 'bool'`

Eigener, methoden-scoped Lockout für die Alt-Passwort-Abfrage der Kontoseite.

### `is_pin_locked(username, ip, login: 'bool' = True) -> 'bool'`

Eigener, methoden-scoped Lockout für PIN (kurzer Keyspace). Zusätzlich zu is_locked().

### `is_reauth_locked(username, ip) -> 'bool'`

Eigener, methoden-scoped Lockout für die Step-up-Bestätigung (`/auth/reauth`).

### `is_resource_locked(username, ip) -> 'bool'`

Eigener, methoden-scoped Lockout für die Bereichs-PIN (`/auth/resource/…`).

### `is_secure(request: 'Request') -> 'bool'`

HTTPS aktiv? (direkt, via X-Forwarded-Proto hinter Proxy, oder localhost).

### `is_totp_setup_locked(username, ip) -> 'bool'`

Eigener, methoden-scoped Lockout für die Bestätigung der TOTP-Einrichtung.

### `issue_csrf(response: 'Response') -> 'str'`

CSRF-Token erzeugen und als Cookie setzen — für eigene Templates (Jinja & Co.), die nicht über `render_page()` laufen. Rückgabe gehört ins Formularfeld `_csrf` bzw. den Header `X-CSRF-Token`. Ist CSRF abgeschaltet, passiert nichts und der Rückgabewert ist leer.

### `json_body(request: 'Request') -> 'dict'`

JSON-Body robust lesen: ungültiger/leerer Body → 400 statt 500. Erzwingt CSRF (Header X-CSRF-Token) für cookie-basierte Clients; API-Key-Requests sind ausgenommen.

### `kennung_vergeben(kennung, exclude_id=None) -> 'Optional[dict]'`

Gehört diese Login-Kennung schon einem Konto — in IRGENDEINEM der beiden Namensräume?

### `list_api_keys(user_id)`

Die API-Keys eines Kontos — ohne die Schlüssel selbst, die gibt es nur einmal bei der Ausgabe.

### `list_resource_secrets()`

Alle gesperrten Ressourcen (Namen und Beschreibungen, keine Geheimnisse).

### `loese_fremde_bindung(quelle: 'str', user_id: 'int') -> 'int'`

Die Bindung eines Kontos an eine fremde Identität lösen (Betreiber-Weg).

### `login_fresh(request: 'Request', user: 'Optional[dict]' = None) -> 'bool'`

True, wenn die **Anmeldung** höchstens `stepup_max_age_sec` zurückliegt.

### `login_redirect_after(request, token, user_id, nxt)`

Zielredirect nach einem Faktor: nxt wenn Sitzung komplett, sonst Eingabeseite des nächsten Faktors.

### `logout(request, response)`

Die Sitzung dieses Requests beenden, die Bereichs-Freigaben dieses Browsers mit, und beide Cookies löschen — dazu die Cookies unter den Namen von vor dem `__Host-`-Präfix.

### `magic_url(raw, base_url, purpose='login') -> 'str'`

Der Link, den der Empfänger anklickt — Pfad je nach Zweck (`TOKEN_PATHS`). `base_url` wird geprüft: ein fremder Host wirft `ConfigError` — in einer Route liefert `public_base(request)` die geprüfte Basis.

### `mail_configured() -> 'bool'`

Kann überhaupt eine Mail hinausgehen — per SMTP oder per `set_mailer`?

### `maybe_promote_admin(user, email_bestaetigt: 'Optional[bool]' = None, faktor: 'Optional[str]' = None) -> 'bool'`

Weg 1: Allowlist. Wer in `admin_identifiers` steht, wird beim Login Admin — egal über welche Methode (auch OIDC/SAML/LDAP); eine Allowlist-ADRESSE aber nur mit einem Beleg, dass sie dem Anmeldenden gehört, und über SAML/LDAP gibt es keinen. Danach nie wieder.

### `mfa_pending(user_id) -> 'bool'`

TOTP verlangt? Ja, wenn ein bestätigtes TOTP für dieses Konto existiert.

### `nach_der_antwort(resp, auftrag, bei_ueberlauf=None)`

`auftrag()` erst NACH dem Versand der Antwort ausführen, im eigenen Mail-Arbeiter (`mailer.Postausgang`, R4-05/B6-6). Gibt `resp` zurück.

### `next_login_step(user_id, done)`

Nächster offener Faktor bis zur vollen (globalen) Anmeldung, oder None wenn fertig.

### `nur_foederiert(user_id) -> 'bool'`

Reines SSO-Konto: an einen IdP/ein Verzeichnis gebunden und ohne lokales Passwort.

### `oidc_anwendung(url_oder_host: 'str') -> 'str'`

Der Client-Schlüssel für diese Adresse — "" wenn diese Installation nur eine Anwendung schützt. Der leere Rückgabewert ist Absicht: Er hält jede Aufrufstelle wortgleich beim Verhalten von 0.18.0, solange `oidc_clients` leer ist.

### `oidc_freigabe_gueltig(token_hash: 'str', client: 'str') -> 'tuple'`

Darf diese Sitzung in diese Anwendung? Rückgabe `(ja, grund)`.

### `own_events(user_id: 'int', limit: 'int' = 20) -> 'list'`

Die jüngsten Audit-Ereignisse eines Kontos, für die Kontoseite (H-7).

### `passwort_mangel(password, username=None, email=None, api: 'bool' = False) -> 'Optional[str]'`

Die Passwortregel für ein NEUES Passwort — `None` heisst „in Ordnung", sonst der übersetzte Grund (`api=True`: der Text für eine JSON-Antwort).

### `peek_magic(raw, purpose=None) -> 'Optional[dict]'`

Token prüfen OHNE ihn zu verbrauchen (für den Invite-Flow: erst bei Registrierung einlösen).

### `pending_user(request) -> 'Optional[dict]'`

User einer Session, die noch im MFA-Schritt hängt (mfa_ok=0).

### `public_base(request: 'Optional[Request]' = None, kandidat: 'str' = '') -> 'str'`

Die öffentliche Basis-URL für alles, was das Haus verlässt — Mail-Links, Redirect-URIs, SAML-Metadaten. Leer heißt: es gibt keine, der Aufrufer bricht ab.

### `purge_demo() -> 'int'`

Die von `seed_demo` angelegten Konten wieder entfernen — genau die, keine gleichnamigen.

### `rate_ok(ip, login: 'bool' = True) -> 'bool'`

Darf diese IP noch? Ein Nein schreibt eine Zeile ins Sicherheits-Log (fail2ban liest mit).

### `record_login(username, ip, success, method, versuch: 'Optional[int]' = None, quelle: 'str' = '')`

Einen Anmeldeversuch verbuchen. Ein Erfolg räumt nur die Fehlversuche DERSELBEN Methode weg.

### `recovery_codes_remaining(user_id) -> 'int'`

Wie viele Einmal-Codes dieses Konto noch hat.

### `redeem_magic(raw, purpose=None) -> 'Optional[dict]'`

Token einlösen (one-shot). Gibt {purpose,user_id,email,payload} oder None (ungültig/abgelaufen/benutzt).

### `remove_resource_secret(name)`

Eine gesperrte Ressource wieder freigeben (die Sperre entfernen, nicht entsperren).

### `render_page(template, status=200, request: 'Optional[Request]' = None, **ctx) -> 'Response'`

`request` mitgeben, wo es eins gibt: dann bleibt ein bereits gesetztes CSRF-Token gültig. Ohne `request` entsteht ein neues — das überschreibt das Cookie und macht *andere* offene Formulare ungültig (klassische „Formular abgelaufen"-Falle).

### `require(mfa: 'bool' = False, admin: 'bool' = False, role=None, factors: 'Optional[list]' = None, strict: 'Optional[bool]' = None, admin_implies: 'Optional[bool]' = None)`

Allgemeine Guard-Factory für beliebige Kombinationen — der „Flag am Guard"-Weg: `Depends(auth.require(mfa=True))`, `Depends(auth.require(admin=True, mfa=True))`. `role=` nimmt eine Rolle oder mehrere (`role=["redaktion", "lektorat"]` → eine genügt). factors=[...] verlangt eine bestimmte Faktor-Kette für diese Route (überschreibt die globale), strict=True/False steuert die Reihenfolge: `Depends(auth.require(factors=['oidc','password']))`.

### `require_admin(request: 'Request') -> 'dict'`

FastAPI-Dependency (direkt): eingeloggt + Admin (+ Step-up, wenn admin_require_mfa).

### `require_csrf(request: 'Request', submitted)`

Für Formular-POSTs: wirft 403, wenn der CSRF-Token fehlt/nicht passt.

### `require_mfa(request: 'Request') -> 'dict'`

FastAPI-Dependency (direkt): eingeloggt + frische Step-up-Bestätigung.

### `require_public_base(request: 'Optional[Request]' = None, kandidat: 'str' = '') -> 'str'`

Wie `public_base()`, nur ohne Rückweg: keine geprüfte Basis → `ConfigError`.

### `require_resource(name: 'str')`

FastAPI-Dependency-Factory: Bereich erst nach Eingabe des Ressourcen-Geheimnisses zugänglich. Unabhängig vom Benutzer-Login. `Depends(auth.require_resource('fotos'))`.

### `require_role(*roles, mfa: 'bool' = False, admin_implies: 'Optional[bool]' = None)`

FastAPI-Dependency-Factory: eingeloggt + Rolle. `Depends(auth.require_role('editor'))`.

### `require_session(request: 'Request', user: 'Optional[dict]' = None) -> 'dict'`

Eingeloggt — und zwar **interaktiv**: eine Sitzung ja, ein API-Key nein (403).

### `require_user(request: 'Request') -> 'dict'`

FastAPI-Dependency (direkt): erzwingt eingeloggten (inkl. MFA) User. Wer keine Rollen braucht: `Depends(auth.require_user)` genügt.

### `resource_unlocked(request: 'Request', name) -> 'bool'`

Ist diese Ressource für diesen Browser gerade freigeschaltet?

### `revoke_api_key(key_id, user_id=None)`

Einen Key entwerten. Er bleibt in der Liste stehen — wer ihn ausgestellt hat, soll das sehen.

### `revoke_mfa_enrollment(user_id: 'int') -> 'None'`

Ein offenes Einrichtungsfenster sofort schliessen.

### `rotate_session(request, response) -> 'Optional[str]'`

Der laufenden Sitzung ein neues Token geben und das Cookie setzen (F-06).

### `router()`

Der FastAPI-Router mit allen aktivierten Routen. Einmal einbinden, fertig.

### `safe_next(next_: 'str') -> 'str'`

?next=-Ziel gegen Open-Redirect absichern (nur relative Pfade bzw. trusted_redirect_hosts).

### `sec(key) -> 'int'`

Härtungs-Wert: Store-Setting (Panel) ODER Default, immer innerhalb von `security.SECURITY_GRENZEN`.

### `seed_demo() -> 'None'`

Beispielkonten anlegen (idempotent). Verlangt `demo_mode=True`.

### `send_login_link(email, base_url, next='/') -> 'bool'`

Login-Link an eine E-Mail schicken, WENN ein passender interaktiver User existiert. Rückgabe nur intern — nach außen immer dieselbe Meldung (keine User-Enumeration). `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

### `send_mail(to, subject, text, html=None)`

Eine Mail versenden — über SMTP oder den per `set_mailer` gesetzten Weg.

### `send_password_reset(email, base_url) -> 'bool'`

Reset-Link an eine E-Mail schicken, WENN ein passender User existiert. Nach außen immer gleiche Meldung (keine Enumeration). `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

### `send_signup_notice(email, base_url) -> 'bool'`

Hinweis an den Inhaber einer Adresse, mit der sich jemand erneut registrieren wollte (R4-03).

### `send_verify_email(user_id, email, base_url) -> 'bool'`

Den Bestätigungslink für eine Adresse verschicken. False, wenn kein Mailer da ist. `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`). Scheitert der Versand, ist der Token entwertet (B6-12) und der Fehler geht weiter.

### `session_from_request(request)`

Die Sitzungszeile zu diesem Request, oder None. `row["token_hash"]` ist ihr Handle.

### `set_cookie(response, token, remember: 'Optional[bool]' = None)`

Session-Cookie setzen. remember=True → persistentes Cookie (max_age = lange TTL); remember=False → reines Session-Cookie (max_age=None, endet beim Browser-Schließen).

### `set_mailer(fn)`

Eigenen Mail-Versand einhängen: fn(to, subject, text, html=None). Überschreibt SMTP.

### `set_password(user_id, password)`

Das Passwort eines Kontos setzen (ohne das alte zu prüfen — das ist Sache des Aufrufers).

### `set_pin(user_id, pin)`

PIN setzen/ändern. Mindestlänge aus cfg.pin_min_length.

### `set_rate_limiter(limiter)`

Eigenes Rate-Limit-Backend einhängen — beliebiges Objekt mit allow(key, max, window)->bool.

### `set_resource_secret(name, secret, kind='pin', label=None)`

Geheimnis für einen Bereich setzen/ändern. kind='pin' (numerisch) \| 'password' (Passphrase).

### `set_roles(user_id, roles)`

Die Rollen eines Kontos ersetzen.

### `set_security(key, value)`

Eine Härtungs-Schwelle zur Laufzeit setzen; sie überlebt den Neustart in der Datenbank.

### `set_template(name, fn)`

Eine eingebaute Seite durch einen eigenen Renderer ersetzen: fn(auth, ctx) -> str \| Response.

### `sicherheitsereignis(ereignis: 'str', user_id, **details) -> 'None'`

`on_security_event` für ein Ereignis aus `SICHERHEITSEREIGNISSE` rufen, falls gesetzt.

### `sperre_aufheben(user_id, methoden=None) -> 'int'`

Die Anmelde-Fehlversuche eines Kontos wegräumen; gibt zurück, wie viele es waren.

### `start_session(user_id, method, ip=None, ua=None, remember: 'bool' = True) -> 'tuple[str, bool]'`

Neue Session mit dem ersten Faktor. Gibt (token, session_ok). session_ok=False → weitere Schritte nötig.

### `stepup_fresh(request: 'Request', user: 'Optional[dict]' = None) -> 'bool'`

True, wenn die aktuelle Sitzung frisch einen Faktor bestätigt hat (Sudo-Frische).

### `stepup_options(user) -> 'list[str]'`

Womit kann DIESER User eine Step-up-Bestätigung leisten? Reihenfolge = Vorschlag.

### `t(key, **fmt) -> 'str'`

Übersetzten Text für key in config.lang (Fallback en → key). Platzhalter via {name}.

### `token_abgewiesen(zweck, request: 'Optional[Request]' = None, grund='ungueltig')`

Ein ungültiger/abgelaufener/verbrauchter Einmal-Token wurde vorgelegt (B5-18).

### `totp_begin(user_id)`

Die Einrichtung starten: liefert Geheimnis und `otpauth://`-Adresse für den Authenticator — und wirft neu `StateError` (kein `ConfigError`, kein stiller Erfolg), wenn das Konto bereits ein bestätigtes TOTP hat.

### `totp_confirm(user_id, code) -> 'bool'`

Die Einrichtung abschliessen — erst mit einem gültigen Code ist TOTP wirklich an.

### `totp_disable(user_id)`

TOTP entfernen, samt der Recovery-Codes (beides wird protokolliert).

### `totp_enrollment_user(request) -> 'Optional[dict]'`

Wer darf TOTP einrichten, **ohne** schon voll angemeldet zu sein? Sonst None.

### `unlock_resource(request: 'Request', response, name)`

Eine Ressource für diesen Browser freischalten und das Cookie setzen.

### `user_roles(user) -> 'list'`

Die Rollen eines Kontos als Liste.

### `verify_api_key(key)`

(user, key_roles\|None) bei gültigem Key, sonst (None, None).

### `verify_csrf(request: 'Request', submitted) -> 'bool'`

Passt das mitgeschickte CSRF-Token zum Cookie? Vergleich in konstanter Zeit.

### `verify_recovery_code(user_id, code) -> 'bool'`

Einen Einmal-Code prüfen und verbrauchen. Ein Code gilt genau einmal.

### `verify_totp(user_id, code) -> 'bool'`

Einen TOTP-Code prüfen — und ihn dabei verbrauchen.

### `verify_user_password(user_id, password) -> 'bool'`

Das Passwort eines BEKANNTEN Kontos prüfen (Step-up: die Identität steht schon fest).

### `verify_user_pin(user_id, pin) -> 'bool'`

Wie `verify_user_password`, nur mit der PIN.

### `vermerke_oidc_freigabe(token: 'str', client: 'str', rollen=None) -> 'None'`

Der Provider hat für diese Anwendung zugestimmt — an der Sitzung vermerken.

### `version() -> 'str'`

Die laufende Version — fürs Panel. TinySesam aktualisiert sich nicht selbst; das erledigt, wer es installiert hat (gepinnter Tag / Wheel eines Releases).

### `versuch_beginnen(username, ip, method, auch_pin: 'bool' = False) -> 'Optional[int]'`

Einen Prüfversuch **atomar** zulassen und vorab als Fehlversuch verbuchen.

## `TinySesamConfig` — Presets

### `TinySesamConfig.active_directory(ldap_url, upn_suffix=None, base_dn=None, bind_dn='', bind_password='', allowed_groups=None, **overrides)`

Preset: Passwort-Login gegen **Active Directory** (via LDAP). Entweder Direkt-Bind per UPN (`upn_suffix="corp.example.com"` → user@corp.example.com) ODER Search-then-Bind über sAMAccountName (`bind_dn`/`bind_password`/`base_dn`). Restliche Felder via **overrides (db_path …).

### `TinySesamConfig.enabled_methods() -> 'list[str]'`

Erstfaktoren, die die Login-Seite anbietet. Eine PIN mit `pin_login=False` steht hier bewusst NICHT — sie bleibt als Zusatzfaktor/Step-up nutzbar.

### `TinySesamConfig.entra_id(tenant_id, client_id, client_secret, oidc_name='Microsoft', **overrides)`

Preset: **Entra ID / Azure AD** via OIDC (Cloud-AD). tenant_id = Verzeichnis-(Tenant-)ID.

### `TinySesamConfig.local_accounts(**overrides)`

Preset: **nur Benutzername + Passwort**, ganz ohne E-Mail.

### `TinySesamConfig.oidc_gateway(issuer, client_id, client_secret, base_url, cookie_domain='', trusted_redirect_hosts=None, allowed_groups=None, group_claim='groups', oidc_name='SSO', oidc_scopes='openid profile email', db_path='tinysesam-gateway.db', https_mode='warn', session_ttl_hours=168, trusted_proxies=None, clients=None, revalidate_minutes=60, **overrides)`

Preset: TinySesam als reines **OIDC-Forward-Auth-Gateway** (Authelia-/oauth2-proxy-Stil). Alle anderen Methoden/Features aus, OIDC + Forward-Auth an. Läuft mit `pip install 'tinysesam[oidc]'`. Einzelne Felder via **overrides überschreibbar.

### `TinySesamConfig.pruefen() -> 'list[str]'`

Die Konfiguration erneut prüfen — für den Fall, dass sie nach dem Aufbau geändert wurde.

## Fehlertypen

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

---

138 Methoden, 6 Presets, 5 Fehlertypen — erzeugt aus den Docstrings.
