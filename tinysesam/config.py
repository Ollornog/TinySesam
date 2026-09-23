"""Konfiguration für TinySesam. Die einbindende App füllt TinySesamConfig und übergibt es an TinySesam()."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class TinySesamConfig:
    # --- Store ---
    db_path: str = "tinysesam.db"

    # --- Sprache der eingebauten Texte (en|de; eigene via auth.add_messages) ---
    lang: str = "en"

    # --- Branding/Theme: einmal setzen → re-skinnt ALLE eingebauten Seiten (+ Fehlerseiten) ---
    brand_css: str = ""                   # zusätzliches CSS (nach dem Default → überschreibt es)
    brand_head: str = ""                  # zusätzliches <head>-HTML (z.B. Logo-Font, Meta)
    brand_icon: str = ""                  # Favicon-URL für ALLE eingebauten Seiten (leer = keins)
    # Rumpf der Host-App um JEDE eingebaute Seite (Login/PIN/TOTP/Konto/Admin/Fehler): eigene
    # Navigation oben, Fußzeile unten. Entweder HTML-String oder `fn(auth) -> str`, wenn der
    # Inhalt vom Request abhängt (Login-Status, Sprache) — dann pro Aufruf ausgewertet.
    brand_header: object = ""
    brand_footer: object = ""         # Fußzeile unter jeder eingebauten Seite; HTML-String oder `fn(auth) -> str`

    # --- Rollen/Gruppen ---
    # Erfüllt ein Admin JEDE require_role(...)-Prüfung? Default True (klassisches Verhalten).
    # ACHTUNG: hängen die Rechte einer App allein an einer IdP-Gruppe, ist das eine stille
    # Rechteausweitung — dann False setzen oder je Guard `require_role(..., admin_implies=False)`.
    admin_implies_roles: bool = True
    # Wie werden IdP-Gruppen mit den Schlüsseln von *_group_role_map verglichen?
    # "exact" (Default, sicher) oder "substring" (alter Teilstring-Vergleich, nur auf Wunsch).
    # LDAP vergleicht bei "exact" einen memberOf-DN nach Bestandteilen: ganzer DN, "cn=staff" oder "staff".
    group_match: str = "exact"
    # Bekannte Rollen/Gruppen: das Admin-Panel bietet sie als Checkboxen an (leer = Freitext-Fallback).
    available_roles: list[str] = field(default_factory=list)
    # IdP-Gruppe → lokale Rolle (beim OIDC/SAML/LDAP-Login gesetzt). Ziel "__admin__" = Admin-Flag (nur grant).
    # Vergleich nach `group_match` (Vorgabe exakt). Managed Rollen werden je Login synchronisiert.
    oidc_group_role_map: dict = field(default_factory=dict)
    saml_group_role_map: dict = field(default_factory=dict) # SAML-Gruppe → lokale Rolle, z.B. `{"staff": "redaktion"}`
    ldap_group_role_map: dict = field(default_factory=dict) # LDAP-Gruppe (DN oder Name) → lokale Rolle

    # --- Aktive Login-Methoden (alle parallel möglich) ---
    password_enabled: bool = True     # Passwort-Login überhaupt anbieten (aus = nur SSO/Passkey/PIN)
    # Eigene Blockliste für neue Passwörter: Pfad zu einer Textdatei, ein Passwort je Zeile
    # (UTF-8, Zeilen in anderer Kodierung gelten als Latin-1; `#` am Zeilenanfang = Kommentar).
    # Ergänzt die kleine eingebaute Liste — wer die gängigen Leak-Listen (z.B. die 100 000
    # häufigsten) abgleichen will, legt sie hier ab. Offline: TinySesam fragt keinen fremden
    # Dienst. Leer = nur die eingebaute Liste. `tinysesam passwd` liest sie mit `--blocklist-file`.
    password_blocklist_file: str = ""
    # Vorgabe AUS, weil `webauthn` nicht im Kern steckt, sondern im Extra [passkey].
    # Stand bis 2026-09-21 auf True — damit stuerzte `pip install tinysesam` mit
    # Vorgabe-Konfiguration beim Bau des Routers ab (ModuleNotFoundError: webauthn).
    # Der allererste Schritt jedes neuen Nutzers, und die Testsuite konnte es nicht sehen.
    passkey_enabled: bool = False         # WebAuthn / Passkeys (passwortlos) — braucht [passkey]
    #: Muss der Authenticator den Menschen prüfen (PIN, Fingerabdruck, Gesicht), bevor er
    #: signiert? `"required"` (Vorgabe) verlangt es, `"preferred"` bittet darum und nimmt auch
    #: ein Nein (B2-10).
    #:
    #: Warum das zählt: Ein Passkey meldet in TinySesam **allein** an — er ist kein zweiter
    #: Faktor, sondern ein vollständiger Login. Ohne Nutzerprüfung belegt er nur den **Besitz**
    #: des Schlüssels: Der entsperrte Rechner, der eingesteckte Stick, das kurz aus der Hand
    #: gelegte Telefon genügen dann. Mit ihr belegt er Besitz **und** etwas, das nur die Person
    #: kann. Bis 0.18.x stand hier „preferred" und die Antwort wurde nicht einmal geprüft — ein
    #: Authenticator konnte also nein sagen und galt trotzdem.
    #:
    #: `"preferred"` ist eine bewusste Entscheidung für einen Bestand alter Authentikatoren und
    #: meldet sich beim Start. Wer neu anfängt, lässt es auf `"required"`.
    passkey_user_verification: str = "required"
    pin_enabled: bool = False             # persönliche PIN pro User (Benutzer + PIN)
    pin_login: bool = True                # PIN als Erstfaktor auf der Login-Seite anbieten.
                                          # False = PIN existiert, dient aber NUR als Zusatzfaktor
                                          # (Route-Kette) bzw. Step-up für sensible Bereiche.
    pin_min_length: int = 4               # Mindestlänge beim Setzen einer PIN
    # Womit bestätigt man einen Step-up (require(mfa=True))? Leer = alles, was der User eingerichtet hat
    # (Reihenfolge totp → pin → password). z.B. ["pin"] = PIN für sensible Bereiche.
    # Hat der User keine der genannten Methoden, greift sein bestes verfügbares Verfahren.
    stepup_methods: list[str] = field(default_factory=list)
    # Aus dem Wunsch eine Schranke machen: True = wer keines der genannten Verfahren eingerichtet
    # hat, kommt NICHT herein (statt mit dem Passwort zu bestätigen, mit dem er sich gerade
    # angemeldet hat — das ist kein Step-up). Vorgabe False, weil der Bereich sonst für Bestands-
    # konten über Nacht verschlossen wäre; wer `stepup_methods` setzt, um etwas zu erzwingen,
    # will in aller Regel True dazu.
    stepup_strict: bool = False
    oidc_enabled: bool = False            # externer IdProvider (PocketID …)
    # Pfad des Callbacks. Muss beim IdP als Redirect-URI hinterlegt sein (base_url + dieser Pfad).
    # Beim Start loggt TinySesam die erwartete URI — Tippfehler fallen sonst erst nach dem Login auf.
    oidc_callback_path: str = "/auth/oidc/callback"
    apikey_enabled: bool = True           # Zugang per API-Key (maschinell/Daemons, an User/Service-Account)
    #: Lebensdauer eines Automaten-Keys in Tagen, wenn der Aufrufer keine nennt. Ein Key ohne
    #: Ablauf ist ein Geheimnis, das niemand mehr zurücknimmt: Er überlebt den Menschen, der ihn
    #: ausgestellt hat, das Projekt, für das er gedacht war, und den Rechner, auf dem er liegt.
    apikey_default_days: int = 90
    #: Darf ein Automaten-Key ohne Ablauf entstehen (`expires_days=0`)? Vorgabe nein. True ist
    #: eine bewusste Entscheidung des Betreibers und wird beim Anlegen protokolliert — es gibt
    #: Fälle dafür (ein Gerät, das niemand anfassen kann), sie sind nur selten.
    apikey_allow_unlimited: bool = False
    admin_enabled: bool = True            # Admin-Panel automatisch unter admin_path mounten
    admin_path: str = "/auth/admin"       # Standard-Mountpunkt; auth.admin_router() lässt es auch woanders montieren
    admin_ui_enabled: bool = True         # eingebaute HTML-UI; False = nur JSON-API (fürs Einbetten in ein eigenes Panel)
    account_enabled: bool = True          # eingebaute Selbstverwaltungs-Seite /auth/account (überschreibbar)
    forward_auth_enabled: bool = False    # /auth/forward + /auth/verify für Reverse-Proxy (Caddy/nginx/Traefik)
    # Welche Header die Forward-Auth-Antwort setzt. Leer = der Authelia-übliche Satz
    # Remote-User/-Name/-Email/-Groups. Sonst **Feld → Headername** (oder Liste von Namen); was hier
    # nicht steht, wird NICHT gesetzt. Felder: user · name · email · groups.
    #   {"user": "X-WEBAUTH-USER"}                     → Grafana-Stil, und sonst nichts
    #   {"user": ["Remote-User", "X-Auth-Request-User"], "groups": "X-Auth-Request-Groups"}
    # Beim Traefik-/Caddy-Beispiel die durchgereichten Header mitziehen (authResponseHeaders).
    forward_headers: dict = field(default_factory=dict)
    https_mode: str = "warn"              # off | warn | force  — force = HTTP→HTTPS-Redirect;
                                          # warn = läuft auch OHNE Zertifikat (mit Warnhinweis im Panel)
    # Womit meldet man sich an? "username" | "email" | "both" (beides im selben Feld erlaubt)
    login_identifier: str = "both"
    # --- Erst-Admin (Bootstrap) — bewusst NICHT "der erste registrierte User wird Admin" ---
    admin_identifiers: list[str] = field(default_factory=list)  # Benutzername/E-Mail, die beim Login
                                          # zum Admin befördert werden, SOLANGE es keinen Admin gibt.
                                          # Funktioniert auch mit OIDC/SAML/LDAP (dort meist die E-Mail).
    admin_claim_ttl_min: int = 60         # Gültigkeit des Einmal-Tokens für /auth/claim-admin (0 = aus)
    # Wohin der Wert des Einmal-Tokens geschrieben wird. Leer = auf stderr (Konsole des
    # Betreibers). Ein Pfad hier: TinySesam legt die Datei mit Rechten 0600 an und schreibt den
    # Token hinein — der richtige Weg, wenn stderr im journal/in einer Sammelstelle landet.
    # Der Token steht NIE im security_log (das liest fail2ban, und logrotate hebt es auf).
    admin_claim_token_file: str = ""      # z.B. /run/tinysesam/admin-claim.token

    # --- Demo-Modus: legt Beispielkonten an und zeigt die Zugangsdaten an. NIEMALS produktiv. ---
    demo_mode: bool = False           # Beispielkonten anlegen und die Zugangsdaten anzeigen — NIEMALS produktiv
    demo_password: str = "demo1234"   # Passwort der Demo-Konten (nur bei demo_mode)
    demo_pin: str = "1234"            # PIN der Demo-Konten (nur bei demo_mode)

    allow_signup: bool = False            # Selbst-Registrierung (lokaler User+Passwort)
    signup_require_email: bool = True     # E-Mail bei der Registrierung Pflicht (eindeutig, s. login_identifier)
    signup_verify_email: bool = False     # Konto erst nach E-Mail-Bestätigung (Magic-Link) aktiv — braucht Mailer
    signup_invite_only: bool = False      # Registrierung nur mit gültigem Einladungs-Token
    signup_default_roles: list[str] = field(default_factory=list)  # Rollen für neue Selbst-Registrierte

    # --- Geteilte Ressourcen-Geheimnisse (ohne Benutzerkonto: eine PIN/Passphrase schützt einen Bereich) ---
    resource_locks_enabled: bool = False # Einzelne Routen/Ressourcen zusätzlich per PIN sperren
    resource_unlock_ttl_hours: int = 12   # wie lange eine freigeschaltete Ressource offen bleibt
    resource_cookie: str = "tinysesam_runlock" # Cookie-Name für entsperrte Ressourcen

    # --- Magic-Link (Einmal-Login/-Zugang per E-Mail) ---
    magiclink_enabled: bool = False   # Anmeldung per Einmal-Link — braucht einen Mailer
    magiclink_ttl_min: int = 15           # Gültigkeit eines Einmal-Links

    # --- E-Mail-Versand (SMTP; per auth.set_mailer(fn) komplett überschreibbar) ---
    smtp_host: str = ""                   # leer + kein set_mailer → Versand deaktiviert
    smtp_port: int = 587              # 587 = STARTTLS, 465 = SMTPS (dann smtp_ssl=True)
    smtp_user: str = ""               # SMTP-Benutzername; leer = ohne Anmeldung senden
    smtp_password: str = ""           # SMTP-Passwort — gehört in eine Umgebungsvariable, nicht in den Quelltext
    smtp_from: str = ""                   # Absender; leer = smtp_user
    smtp_starttls: bool = True            # 587 = STARTTLS; für 465 smtp_ssl=True setzen
    smtp_ssl: bool = False            # SMTPS ab Verbindungsaufbau (Port 465) statt STARTTLS
    smtp_timeout: int = 15            # Sekunden, bis ein hängender Mailserver aufgibt
    smtp_ca_file: str = ""            # eigene CA (PEM) für das Relay; leer = System-CAs. Geprüft wird immer
    mail_subject_prefix: str = ""         # optionaler Betreff-Präfix, z.B. "[MeineApp] "

    # --- TOTP (2FA on-top zu Passwort/OIDC; Passkeys sind schon phishing-resistent) ---
    totp_enabled: bool = True             # User dürfen TOTP einrichten
    # ACHTUNG: wirkungslos und deshalb seit 0.18.0 ABGEWIESEN — der Schalter wurde nie
    # gelesen. TOTP verbindlich verlangen geht über die Faktor-Kette:
    #   login_chain=['password', 'totp']  (+ login_chain_strict=True)
    # Das Feld bleibt nur stehen, damit ein bestehender Aufruf einen klaren Fehler bekommt
    # statt eines TypeError über ein unbekanntes Argument.
    totp_required: bool = False
    recovery_code_count: int = 10         # Anzahl Einmal-Recovery-Codes je Erzeugung (verlorener Authenticator)

    # --- Passwort-Reset (Forgot-Password per E-Mail; braucht magiclink_enabled + Mailer) ---
    password_reset_enabled: bool = False

    # --- Faktor-Ketten (geordnete Kombinationen) ---
    # Globale Standard-Kette erfüllter Faktoren, die eine Sitzung vollständig macht, z.B.
    # ["oidc", "password"] oder ["password", "totp"]. Leer = klassisch (ein Erstfaktor + TOTP falls
    # eingerichtet). Pro Route überschreibbar: Depends(auth.require(factors=[...], strict=...)).
    # Faktornamen: password, pin, oidc, passkey, totp, magic. Der erste Faktor identifiziert den User.
    login_chain: list[str] = field(default_factory=list)
    #: Wer darf einen von der Kette verlangten zweiten Faktor **selbst** einrichten? (R3-1)
    #:
    #: `login_chain=["password", "totp"]` liest sich wie „ohne zweiten Faktor kommt niemand
    #: rein". Bis 0.18.x stimmte das nicht: Ein Konto ohne TOTP durfte es an genau dieser Stelle
    #: selbst einrichten — wer also nur das Passwort hatte, band seinen eigenen Authenticator ein
    #: und war voll drin. Die Kette schützte damit alle ausser denen, für die sie gedacht war.
    #:
    #: * ``"first_login"`` (Vorgabe): erlaubt, solange das Konto noch **nie** vollständig
    #:   angemeldet war. Ein frisch angelegtes Konto richtet sich beim ersten Mal ein — danach
    #:   nie wieder. Ohne Frist: Wer sein neues Konto erst in drei Wochen benutzt, soll nicht vor
    #:   einer verschlossenen Tür stehen.
    #: * ``"grace"``: erlaubt innerhalb von `mfa_enrollment_grace_days` nach der Kontoanlage.
    #: * ``"strict"``: nie. Die Einrichtung kommt dann vom Betreiber
    #:   (`auth.grant_mfa_enrollment(uid)`, Admin-Panel oder Einladung).
    #:
    #: Verlangt die Kette gar keinen zweiten Faktor, greift nichts davon — ein freiwilliges TOTP
    #: richtet jeder Angemeldete jederzeit selbst ein, wie bisher.
    mfa_enrollment: str = "first_login"
    #: Nur für `mfa_enrollment="grace"`: Tage ab Kontoanlage.
    mfa_enrollment_grace_days: int = 7
    login_chain_strict: bool = True       # Reihenfolge erzwingen (True) oder beliebig (False)

    # --- Step-up / per-Route-MFA (Sudo-Frische) ---
    # Guards mit mfa=True verlangen eine „frische" Faktor-Bestätigung. Frisch ist eine Sitzung
    # stepup_max_age_sec lang nach Login/Reauth; danach → /auth/reauth. 0 = nie ablaufen (nur „hat 2FA bestanden").
    # Dieselbe Spanne begrenzt die Anlage des ERSTEN Faktors: Ein Konto ohne Passwort, PIN und TOTP
    # kann keinen Step-up leisten (`stepup_options()` leer, die Reauth-Seite hat kein Feld), darum
    # zählt dort das Alter der ANMELDUNG (`login_fresh()`) — danach hilft nur ein neuer Login.
    stepup_max_age_sec: int = 900         # 15 min; begrenzt auch die Anlage des ERSTEN Faktors (dort ab Login gemessen)
    admin_require_mfa: bool = False        # Admin-Panel + require_admin verlangen zusätzlich Step-up-MFA

    # --- Sessions (server-side, revozierbar) ---
    session_cookie: str = "tinysesam_session" # Name des Sitzungs-Cookies (bei mehreren Apps auf einer Domain unterscheiden)
    session_ttl_hours: int = 24 * 7       # TTL bei „Angemeldet bleiben" (persistentes Cookie)
    session_ttl_transient_hours: int = 12 # TTL ohne „Angemeldet bleiben" (Session-Cookie, endet beim Browser-Schließen)
    remember_me_enabled: bool = True      # „Angemeldet bleiben"-Checkbox anbieten (aus → immer persistent)
    cookie_secure: bool = True            # nur über HTTPS senden
    cookie_samesite: str = "lax"          # lax|strict|none
    cookie_path: str = "/"            # Pfad, für den die Cookies gelten
    cookie_domain: str = ""               # leer = Host-only; für SSO über Subdomains z.B. ".example.com"

    # --- Content-Security-Policy für die EIGENEN Seiten (Login/Account/TOTP/…) ---
    # Die eingebauten Seiten sind nonce-fest gebaut (kein Inline-Handler, kein style=);
    # pro Antwort wird ein Nonce erzeugt und in jedes <script>/<style> injiziert.
    #   "strict" (Default) → default-src 'self'; script-src/style-src nur per Nonce
    #   "off"              → kein CSP-Header (z.B. wenn ein Proxy/eine App die CSP zentral setzt)
    #   eigener String     → 1:1 als Header; ein enthaltenes {nonce} wird ersetzt. Ohne eine
    #                        einzige bekannte Direktive ('Strict', 'stirct') bricht der Aufbau
    #                        ab, statt die CSP still abzuschalten; eine unbekannte neben
    #                        bekannten ('scirpt-src', 'require-sri-for') gibt eine Warnung
    # Gilt für die von TinySesam gerenderten Seiten und das Admin-Panel, nicht für eigene
    # Response-Overrides (die setzen ihre CSP selbst). Bei 'strict' kommt X-Frame-Options:
    # SAMEORIGIN dazu; nosniff, Referrer-Policy, no-store und Vary: Cookie tragen alle
    # TinySesam-Antworten unabhängig von diesem Schalter.
    csp: str = "strict"

    # --- CSRF (Double-Submit-Cookie; zusätzlich zu SameSite=Lax) ---
    csrf_enabled: bool = True             # State-ändernde POSTs verlangen Token (Formular _csrf / Header X-CSRF-Token)
    csrf_cookie: str = "tinysesam_csrf" # Name des CSRF-Cookies

    # --- LDAP / lldap (Passwort gegen Verzeichnis-Bind; zählt als Faktor 'password') ---
    #: Muss eine fremde Identität (LDAP, SAML) eine stabile Kennung mitbringen? Vorgabe **nein**:
    #: Ein Verzeichnis, das keine liefert, soll nach dem Update nicht plötzlich niemanden mehr
    #: anmelden. Fehlt sie, fällt die Zuordnung auf den Benutzernamen zurück — den ungeschützten
    #: Zustand von vor 0.20.0 — und sagt das einmal je Quelle im Sicherheits-Log. True macht
    #: daraus eine Abweisung; das ist die sichere Einstellung, sobald das Verzeichnis kann.
    federation_require_stable_id: bool = False
    ldap_enabled: bool = False        # Passwörter gegen ein LDAP/AD prüfen statt lokal — braucht [ldap]
    ldap_url: str = ""                    # ldap://host:389 oder ldaps://host:636
    ldap_start_tls: bool = False      # Nach dem Verbinden auf TLS hochschalten (Port 389); für 636 `ldaps://` in der URL
    #: Das Zertifikat des Verzeichnisses prüfen? Vorgabe **ja** (F-12). Ohne die Prüfung ist
    #: verschlüsselt nur „nicht mitlesbar von jemandem, der nicht dazwischensitzt": Wer den
    #: Verkehr umlenkt, hält ein eigenes Zertifikat hin, bekommt das Passwort des Dienstkontos
    #: und jedes Benutzerpassworts, und reicht die Antwort weiter — niemand merkt etwas.
    #: Bis 0.19.0 gab es die Prüfung gar nicht.
    ldap_tls_verify: bool = True
    #: Eigene CA-Datei (PEM) für das Verzeichnis-Zertifikat. Leer = der Speicher des Systems.
    #: Der übliche Weg bei einem internen Verzeichnis mit eigener CA.
    ldap_tls_ca_file: str = ""
    #: Darf ganz ohne TLS gesprochen werden (`ldap://` ohne StartTLS)? Vorgabe **nein**. Dann
    #: gingen das Passwort des Dienstkontos und jedes Benutzerpasswort im Klartext über das Netz.
    #: True ist eine bewusste Entscheidung für ein Verzeichnis auf demselben Host (Loopback) und
    #: meldet sich beim Start.
    ldap_allow_plaintext: bool = False
    ldap_user_dn_template: str = ""       # Direkt-Bind, z.B. "uid={username},ou=people,dc=example,dc=com" (lldap)
    ldap_bind_dn: str = ""                # ODER Service-Account für Search-then-Bind
    ldap_bind_password: str = ""      # Passwort des Service-Accounts — gehört in eine Umgebungsvariable
    ldap_user_base: str = ""              # Suchbasis (bei Search-then-Bind)
    ldap_user_filter: str = "(uid={username})" # Suchfilter für das Konto; `{username}` wird eingesetzt
    #: Das Attribut mit der **stabilen** Kennung des Verzeichniseintrags (F-11). Leer = der
    #: Reihe nach `entryUUID` (OpenLDAP, lldap) und `objectGUID` (Active Directory) versuchen.
    #: Daran hängt die Zuordnung zum lokalen Konto — ein Benutzername taugt dafür nicht: Wer im
    #: Verzeichnis umbenennt oder ein gelöschtes Konto unter demselben Namen neu anlegt, bekäme
    #: sonst dasselbe lokale Konto mitsamt seinen Rollen.
    ldap_attr_id: str = ""
    ldap_attr_email: str = "mail"     # LDAP-Attribut mit der E-Mail-Adresse
    ldap_attr_name: str = "cn"        # LDAP-Attribut mit dem Anzeigenamen
    ldap_group_attr: str = "memberOf"     # Attribut mit Gruppen-Zugehörigkeit
    ldap_allowed_groups: list[str] = field(default_factory=list)  # leer = alle; sonst Gate (DN, "cn=x" oder "x" — kein Teilstring)
    ldap_auto_create: bool = True         # unbekannten LDAP-User lokal anlegen (ohne lokales Passwort)

    # --- OIDC ---
    oidc_name: str = "SSO"                # Anzeigename des Buttons
    oidc_issuer: str = ""                 # z.B. https://id.example.com  (…/.well-known/openid-configuration)
    oidc_client_id: str = ""          # Client-ID beim Provider
    oidc_client_secret: str = ""      # Client-Secret — gehört in eine Umgebungsvariable, nicht in den Quelltext
    oidc_scopes: str = "openid profile email" # Angeforderte Scopes; `openid` ist Pflicht, `email`/`profile` füllen das Konto
    oidc_auto_create: bool = True         # unbekannten OIDC-User automatisch anlegen
    # Was gilt, wenn der Provider `email_verified` NICHT schickt? Der Claim ist in OIDC Core 5.1
    # optional (Entra ID etwa lässt ihn weg). Vorgabe False = die Adresse gilt als unbestätigt:
    # Sie wird ganz normal ins Konto übernommen und weitergereicht (`Remote-Email`), trägt aber
    # keine Rechte — Erst-Admin über `admin_identifiers` verlangt den Beleg (vermerkt als
    # `users.email_verified=0`, gilt dann für JEDEN Anmeldeweg dieses Kontos). True nur für IdPs,
    # die den Claim nicht schicken UND deren Adressen der Betreiber selbst verantwortet (eigenes
    # Verzeichnis, ein Mandant): dann zählt eine Adresse ohne Claim als belegt und kann den
    # Erst-Admin tragen. Ein Claim, der ausdrücklich `false` sagt, bleibt in beiden Fällen Nein.
    oidc_email_verified_default: bool = False
    oidc_rp_logout: bool = False          # beim Abmelden auch den OIDC-Provider abmelden (end_session), optional
    oidc_group_claim: str = "groups"      # Claim mit den Gruppen
    oidc_allowed_groups: list[str] = field(default_factory=list)  # leer = alle erlaubt

    # --- Mehrere Anwendungen hinter EINER Installation (T-14) ---
    #: Geschützter Host → eigener OIDC-Client beim selben Provider. Leer = eine Anwendung, der
    #: Einzel-Client oben gilt für alles (Verhalten bis 0.18.0, unverändert).
    #:
    #: Warum überhaupt: Wer in welche Anwendung darf, entscheidet der **Provider** — bei PocketID
    #: über die Gruppenfreigabe je OIDC-Client. Diese Freigabe hängt am Client, nicht am Benutzer.
    #: Mit einem einzigen Client gibt es deshalb nur eine Antwort für alle Anwendungen: Wer bei
    #: irgendeiner drin ist, ist bei allen drin. Die bisherige Abhilfe war eine eigene
    #: TinySesam-Instanz je Anwendung — drei Container, drei Datenbanken, drei Audit-Logs für
    #: dieselben Menschen.
    #:
    #: Aufbau je Eintrag: ``{"app.example.com": {"client_id": "...", "client_secret": "...",
    #: "scopes": "openid profile email", "allowed_groups": [...], "group_role_map": {...}}}``.
    #: Fehlt ein optionaler Schlüssel, gilt der Wert des Einzel-Clients. Der **Issuer ist für
    #: alle Clients derselbe** — mehrere Provider in einer Instanz sind nicht vorgesehen, und die
    #: Konfigurationsprüfung sagt das auch.
    oidc_clients: dict = field(default_factory=dict)
    #: Nach wie vielen Minuten eine erteilte Freigabe beim Provider nachgeprüft wird. 0 = nie
    #: (Verhalten bis 0.18.0). Der Provider entscheidet über die Freigabe, also muss ein Entzug
    #: dort auch ankommen: Ohne Nachprüfung gilt sie bis zum Ablauf der Sitzung — in der Vorgabe
    #: sieben Tage. Die Nachprüfung ist ein Sprung über den Provider; dessen Sitzung besteht in
    #: aller Regel weiter, der Mensch sieht also nur eine kurze Umleitung. Lehnt der Provider ab,
    #: ist die Freigabe **für diese eine Anwendung** weg, die Sitzung für die anderen bleibt.
    #: ``oidc_gateway()`` setzt 60; wer es von Hand aufbaut, entscheidet selbst.
    oidc_revalidate_minutes: int = 0

    # --- SAML 2.0 (SP-Login gegen einen IdP: ADFS, Keycloak, Okta, Entra …) ---
    saml_enabled: bool = False        # SAML-2.0-Anmeldung gegen einen IdP — braucht [saml] und libxmlsec1
    saml_name: str = "SAML"               # Anzeigename des Buttons
    saml_sp_entity_id: str = ""           # eigene SP-Entity-ID; leer = base_url + /auth/saml/metadata
    saml_acs_url: str = ""                # Assertion Consumer Service; leer = base_url + /auth/saml/acs
    # IdP-Entity-ID. Leer = es wird die SSO-URL angenommen — das stimmt bei manchen IdPs, bei
    # anderen NICHT: Keycloak etwa nennt sich `https://…/realms/<realm>`, während die SSO-URL auf
    # `/protocol/saml` endet. Passt es nicht, wird jede Assertion abgelehnt („Invalid issuer");
    # der Grund steht dann im Logger `tinysesam.security`. Im Zweifel aus dem IdP-Descriptor
    # abschreiben (`entityID=` im Metadata-XML).
    saml_idp_entity_id: str = ""
    saml_idp_sso_url: str = ""            # IdP Single-Sign-On-URL (Redirect-Binding)
    saml_idp_x509cert: str = ""           # IdP-Signaturzertifikat (PEM-Body, ohne BEGIN/END)
    saml_attr_username: str = ""          # Attribut mit dem Benutzernamen; leer = NameID
    saml_attr_email: str = "email"    # SAML-Attribut mit der E-Mail-Adresse
    saml_attr_name: str = "displayName" # SAML-Attribut mit dem Anzeigenamen
    #: Das Attribut mit der **stabilen** Kennung (F-11). Leer = die `NameID` der Assertion.
    #: Sie taugt nur, wenn ihr Format dauerhaft ist: `persistent` oder eine eigene Kennung aus
    #: dem Verzeichnis. Ein **transientes** NameID-Format wechselt bei jeder Anmeldung und ist
    #: als Bindung wertlos — dann gehört hier ein Attribut hin, das der IdP verlässlich schickt.
    saml_attr_id: str = ""
    saml_attr_groups: str = "groups"  # SAML-Attribut mit den Gruppen (für saml_group_role_map)
    saml_allowed_groups: list[str] = field(default_factory=list)  # leer = alle
    saml_auto_create: bool = True     # Unbekannte Nutzer beim ersten erfolgreichen SAML-Login anlegen

    # --- WebAuthn / Passkey ---
    rp_id: str = "localhost"              # Registrable Domain (z.B. app.example.com) — OHNE Schema/Port
    rp_name: str = "TinySesam"            # Anzeigename der Relying Party
    origin: str = "http://localhost:8000" # exaktes Origin (Schema+Host+Port) des Browsers; mehrere als Liste

    # --- App-Integration ---
    # Öffentliche Base-URL — die eine Adresse, unter der die App von außen erreichbar ist.
    # Quelle für JEDE absolute Adresse: Links in Mails (Reset, Magic, Bestätigung, Einladung),
    # OIDC-Redirect-URI und Post-Logout, SAML-Entity-ID/ACS, Forward-Auth-Umleitung.
    # PFLICHT, sobald ein Mail-Weg (magiclink_enabled, password_reset_enabled,
    # signup_verify_email), oidc_enabled oder saml_enabled an ist — sonst scheitert der Aufbau
    # mit ConfigError. Grund: Als Quelle bliebe der Host-Header, und der ist eine Eingabe des
    # Anfragenden; ohne base_url konnte ein Angreifer den Reset-Link in der Mail des Opfers auf
    # seinen Server umbiegen. trusted_redirect_hosts ist dafür kein Ersatz — steht dort mehr als
    # ein Host, wählt der Anfragende per Host-Header aus.
    # Mit Unterpfad montiert (root_path) gehört das Präfix HIER hinein:
    # "https://example.com/sso" — es gilt für die VERSCHICKTEN LINKS, die es genau einmal tragen.
    # Die eingebauten Seiten tragen es nicht (ihre Ziele stehen wurzel-absolut: /auth/register,
    # /auth/forgot, ...), hinter einem Proxy, der das Präfix abschneidet, landet die Anmeldung
    # also im 404, während die Mails funktionieren — backlog/T-15.
    # Wo base_url leer bleiben darf (nur Passwort/Passkey/PIN/LDAP,
    # höchstens forward_auth_enabled), wird eine abgeleitete Basis geprüft: nur ein Host aus
    # trusted_redirect_hosts oder Loopback zählt, und der root_path des Servers kommt mit.
    # Steht base_url, gewinnt sie IMMER — auch gegen eine von außen übergebene Basis auf einem
    # zweiten eigenen Host aus trusted_redirect_hosts (sonst wählt der Host-Header aus, welcher
    # der eigenen Namen in den Reset-Link kommt).
    base_url: str = ""
    login_path: str = "/auth/login"       # Login-Seite
    login_redirect: str = "/"             # Ziel nach erfolgreichem Login
    logout_redirect: str = "/auth/login"  # Ziel nach Logout

    # --- Härtung ---
    # Reverse-Proxies, deren X-Forwarded-For vertraut werden darf (sonst ist die echte Client-IP fälschbar).
    # Nur von diesen Peers wird X-Forwarded-For geglaubt — sonst ist die Client-IP fälschbar
    # (Rate-Limit, Lockout, fail2ban). WICHTIG: uvicorn **ohne** `--proxy-headers` starten. Sonst
    # ersetzt uvicorn `request.client.host` bereits durch die geforwardete IP und diese Prüfung
    # läuft ins Leere.
    trusted_proxies: list[str] = field(default_factory=lambda: ["127.0.0.1/32", "::1/128"])
    # Prozessübergreifendes Rate-Limit über Redis (Multi-Worker); leer = In-Memory pro Prozess. Extra [redis].
    redis_url: str = ""                   # z.B. redis://localhost:6379/0
    # Hosts, auf die ?next= absolut zeigen darf (Open-Redirect-Schutz; leer = nur relative Pfade).
    # Der Host der eigenen base_url zählt immer mit und muss hier nicht wiederholt werden.
    trusted_redirect_hosts: list[str] = field(default_factory=list)
    # Datei, in die der Logger "tinysesam.security" zusätzlich schreibt — das Lesefutter für
    # fail2ban (deploy/fail2ban/), z.B. /var/log/tinysesam/security.log. Leer = nur an den
    # Logger; wer das Logging selbst einrichtet, lässt es leer. Ist die Datei nicht schreibbar,
    # warnt TinySesam und läuft weiter. NEU angelegt wird sie mit 0640 statt mit der umask (auch
    # die nach einer Rotation), denn darin stehen Benutzernamen und IP-Adressen; eine schon
    # vorhandene welt-lesbare Datei wird gemeldet, aber nicht umgeschrieben. Soll ein DRITTER
    # Benutzer mitlesen (Log-Versand, weder Eigentümer noch in der Gruppe), führt der Weg über
    # die Gruppe: logrotate-Zeile `create 0640 tinysesam adm` (steht so in
    # deploy/fail2ban/tinysesam-jail.conf). Ohne sie entsteht die Datei bei der nächsten
    # Rotation wieder mit der Gruppe des TinySesam-Prozesses, und der Versand verliert den
    # Lesezugriff — nicht beim Update, sondern erst bei der Rotation.
    security_log: str = ""
    # Aufbewahrung des Audit-Logs in Tagen: `auth.gc()` löscht ältere Zeilen (B5-11). 0 = keine
    # Frist, das Log wächst wie bisher unbegrenzt. Im Audit-Log stehen Benutzernamen und IPs,
    # also personenbezogene Daten — eine Frist ist Sache des Betreibers (Zweck und Dauer gehören
    # in sein Verarbeitungsverzeichnis). Die Vorgabe löscht deshalb nichts von selbst. Das
    # Kommando `tinysesam gc --audit-days N` tut dasselbe von der Kommandozeile.
    audit_retention_days: int = 0
    # IPs im Audit-Log auf ihr Netz kürzen (IPv4 /24, IPv6 /48). Gilt für neue Zeilen; Sperre,
    # Rate-Limit und security_log (fail2ban) sehen weiterhin die volle Adresse, sonst träfe eine
    # Sperre das ganze Netz.
    audit_ip_pseudonymize: bool = False
    # Feineinstellung (Versuche/Sperrzeit/Rate-Limit) liegt im Store und ist im Admin-Panel änderbar
    # (Defaults: tinysesam.security.SECURITY_DEFAULTS).

    @classmethod
    def local_accounts(cls, **overrides):
        """Preset: **nur Benutzername + Passwort**, ganz ohne E-Mail.

        Schaltet alles ab, was eine Adresse voraussetzt (Magic-Link, Passwort-vergessen,
        E-Mail-Bestätigung) und lässt den Login nur den Benutzernamen annehmen. Ideal für interne
        Werkzeuge ohne Mailserver. Mit `pin_enabled=True` lässt sich eine PIN dazunehmen —
        z.B. `stepup_methods=["pin"]` für sensible Bereiche.
        """
        base = dict(login_identifier="username", signup_require_email=False,
                    signup_verify_email=False, magiclink_enabled=False, password_reset_enabled=False)
        base.update(overrides)
        # `base` ist ein Dict gemischter Werte; die Feldtypen prüft die Dataclass zur Laufzeit.
        return cls(**base)   # type: ignore[arg-type]

    @classmethod
    def oidc_gateway(cls, *, issuer, client_id, client_secret, base_url,
                     cookie_domain="", trusted_redirect_hosts=None, allowed_groups=None,
                     group_claim="groups", oidc_name="SSO", oidc_scopes="openid profile email",
                     db_path="tinysesam-gateway.db", https_mode="warn", session_ttl_hours=24 * 7,
                     trusted_proxies=None, clients=None, revalidate_minutes=60, **overrides):
        """Preset: TinySesam als reines **OIDC-Forward-Auth-Gateway** (Authelia-/oauth2-proxy-Stil).
        Alle anderen Methoden/Features aus, OIDC + Forward-Auth an. Läuft mit `pip install 'tinysesam[oidc]'`.
        Einzelne Felder via **overrides überschreibbar.

        `clients` schützt **mehrere Anwendungen** mit einer Installation: Host → eigener Client
        beim selben Provider (T-14). Ohne die Angabe gilt der Einzel-Client für alles, genau wie
        bisher.

        `revalidate_minutes` steht hier auf **60**, nicht auf 0 wie im Grundaufbau: Ein Gateway
        ist der Ort, an dem die Freigabe des Providers die einzige Autorisierung ist. Bliebe sie
        bis zum Sitzungsende gültig, wirkte ein Gruppenentzug dort bis zu `session_ttl_hours`
        nicht — in der Vorgabe sieben Tage.

        Warum eine Stunde und nicht weniger: Jede Nachprüfung ist ein Sprung über den Provider.
        Für einen Menschen am Browser ist das ein Flackern, für alles andere ein Bruch — ein
        offenes Formular, ein laufender Upload, eine XHR-Anfrage im Hintergrund. Je kürzer die
        Frist, desto öfter trifft es einen davon. Eine Stunde ist gegenüber sieben Tagen die
        Größenordnung, auf die es ankommt; der Unterschied zwischen 15 und 60 Minuten ist für
        einen Entzug selten entscheidend, für den Betrieb dagegen schon. Wer es enger braucht,
        setzt es enger."""
        base = dict(
            db_path=db_path,
            password_enabled=False, passkey_enabled=False, pin_enabled=False,
            oidc_enabled=True, magiclink_enabled=False, apikey_enabled=False,
            allow_signup=False, admin_enabled=False, account_enabled=False,
            totp_enabled=False, resource_locks_enabled=False,
            forward_auth_enabled=True,
            oidc_issuer=issuer, oidc_client_id=client_id, oidc_client_secret=client_secret,
            oidc_name=oidc_name, oidc_scopes=oidc_scopes,
            oidc_allowed_groups=list(allowed_groups or []), oidc_group_claim=group_claim,
            oidc_auto_create=True,
            oidc_clients=dict(clients or {}), oidc_revalidate_minutes=revalidate_minutes,
            base_url=base_url, cookie_domain=cookie_domain,
            trusted_redirect_hosts=list(trusted_redirect_hosts or []),
            session_ttl_hours=session_ttl_hours, https_mode=https_mode,
            trusted_proxies=list(trusted_proxies or ["127.0.0.1/32", "::1/128"]),
        )
        base.update(overrides)
        # `base` ist ein Dict gemischter Werte; die Feldtypen prüft die Dataclass zur Laufzeit.
        return cls(**base)   # type: ignore[arg-type]

    @classmethod
    def active_directory(cls, *, ldap_url, upn_suffix=None, base_dn=None, bind_dn="", bind_password="",
                         allowed_groups=None, **overrides):
        """Preset: Passwort-Login gegen **Active Directory** (via LDAP). Entweder Direkt-Bind per UPN
        (`upn_suffix="corp.example.com"` → user@corp.example.com) ODER Search-then-Bind über
        sAMAccountName (`bind_dn`/`bind_password`/`base_dn`). Restliche Felder via **overrides (db_path …)."""
        base = dict(
            ldap_enabled=True, ldap_url=ldap_url, ldap_group_attr="memberOf",
            ldap_allowed_groups=list(allowed_groups or []), ldap_auto_create=True,
            ldap_attr_email="mail", ldap_attr_name="displayName",
        )
        if upn_suffix:
            base["ldap_user_dn_template"] = "{username}@" + upn_suffix.lstrip("@")
        else:
            base.update(ldap_bind_dn=bind_dn, ldap_bind_password=bind_password,
                        ldap_user_base=base_dn or "", ldap_user_filter="(sAMAccountName={username})")
        base.update(overrides)
        # `base` ist ein Dict gemischter Werte; die Feldtypen prüft die Dataclass zur Laufzeit.
        return cls(**base)   # type: ignore[arg-type]

    @classmethod
    def entra_id(cls, *, tenant_id, client_id, client_secret, oidc_name="Microsoft", **overrides):
        """Preset: **Entra ID / Azure AD** via OIDC (Cloud-AD). tenant_id = Verzeichnis-(Tenant-)ID."""
        base = dict(
            oidc_enabled=True,
            oidc_issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            oidc_client_id=client_id, oidc_client_secret=client_secret,
            oidc_name=oidc_name, oidc_scopes="openid profile email",
        )
        base.update(overrides)
        # `base` ist ein Dict gemischter Werte; die Feldtypen prüft die Dataclass zur Laufzeit.
        return cls(**base)   # type: ignore[arg-type]

    def pruefen(self) -> list[str]:
        """Die Konfiguration erneut prüfen — für den Fall, dass sie nach dem Aufbau geändert wurde.

        `TinySesam` prüft im Konstruktor und hält danach eine **Referenz** auf dieses Objekt:
        Wer Felder nachträglich setzt (`auth.cfg.cookie_samesite = "Strict"`), umgeht damit jeden
        Wächter, und die Werte werden zur Request-Zeit gelesen. Das ist kein theoretischer Fall —
        `examples/showcase.py` ändert `auth.cfg` nach dem Aufbau, und für Sprache oder Branding
        ist das auch völlig in Ordnung.

        Heikel sind nur die Felder, aus denen Cookies und Header entstehen. Wer zur Laufzeit an
        der Konfiguration dreht, ruft danach diese Methode und bekommt eine Liste der Befunde
        (leer = in Ordnung). Ein Einfrieren der Dataclass wäre die härtere Lösung — sie würde
        aber auch das Erlaubte verbieten.
        """
        fehler, warnungen = self._befunde()
        return fehler + warnungen

    def _befunde(self) -> tuple[list[str], list[str]]:
        """(Fehler, Warnungen) getrennt — `pruefen()` gibt beides in einer Liste zurück, und aus
        der liess sich nicht mehr lesen, was den Aufbau hätte scheitern lassen. `TinySesam.router()`
        braucht genau diese Unterscheidung (B3-14)."""
        from .konfigpruefung import pruefe
        fehler, warnungen = pruefe(self)
        if self.cookie_samesite not in ("lax", "strict", "none"):
            fehler.append(f"cookie_samesite={self.cookie_samesite!r} — erlaubt sind 'lax', "
                          "'strict', 'none' (klein geschrieben)")
        if self.cookie_samesite == "none" and not self.cookie_secure:
            fehler.append("cookie_samesite='none' ohne cookie_secure=True — der Browser "
                          "verwirft so ein Cookie")
        if self.https_mode not in ("off", "warn", "force"):
            fehler.append(f"https_mode={self.https_mode!r} — erlaubt sind 'off', 'warn', 'force'")
        if not isinstance(self.csp, str):
            fehler.append(f"csp muss ein String sein, ist {type(self.csp).__name__}")
        if not self.cookie_secure and self.https_mode == "force":
            fehler.append("https_mode='force' mit cookie_secure=False — das Sitzungs-Cookie ginge "
                          "ohne Secure-Flag hinaus")
        return fehler, warnungen

    def enabled_methods(self) -> list[str]:
        """Erstfaktoren, die die Login-Seite anbietet. Eine PIN mit `pin_login=False` steht hier
        bewusst NICHT — sie bleibt als Zusatzfaktor/Step-up nutzbar."""
        m = []
        if self.password_enabled:
            m.append("password")
        if self.pin_enabled and self.pin_login:
            m.append("pin")
        if self.passkey_enabled:
            m.append("passkey")
        if self.oidc_enabled and self.oidc_issuer and self.oidc_client_id:
            m.append("oidc")
        if self.saml_enabled and self.saml_idp_sso_url and self.saml_idp_x509cert:
            m.append("saml")
        if self.magiclink_enabled:
            m.append("magic")
        return m
