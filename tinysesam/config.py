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

    # --- Rollen/Gruppen ---
    # Bekannte Rollen/Gruppen: das Admin-Panel bietet sie als Checkboxen an (leer = Freitext-Fallback).
    available_roles: list[str] = field(default_factory=list)
    # IdP-Gruppe → lokale Rolle (beim OIDC/SAML/LDAP-Login gesetzt). Ziel "__admin__" = Admin-Flag (nur grant).
    # Match ist Teilstring (deckt auch LDAP-memberOf-DNs ab). Managed Rollen werden je Login synchronisiert.
    oidc_group_role_map: dict = field(default_factory=dict)
    saml_group_role_map: dict = field(default_factory=dict)
    ldap_group_role_map: dict = field(default_factory=dict)

    # --- Aktive Login-Methoden (alle parallel möglich) ---
    password_enabled: bool = True
    passkey_enabled: bool = True          # WebAuthn / Passkeys (passwortlos)
    pin_enabled: bool = False             # persönliche PIN pro User (Benutzer + PIN)
    pin_min_length: int = 4               # Mindestlänge beim Setzen einer PIN
    oidc_enabled: bool = False            # externer IdProvider (PocketID …)
    apikey_enabled: bool = True           # Zugang per API-Key (maschinell/Daemons, an User/Service-Account)
    admin_enabled: bool = True            # Admin-Panel automatisch unter admin_path mounten
    admin_path: str = "/auth/admin"       # Standard-Mountpunkt; auth.admin_router() lässt es auch woanders montieren
    admin_ui_enabled: bool = True         # eingebaute HTML-UI; False = nur JSON-API (fürs Einbetten in ein eigenes Panel)
    account_enabled: bool = True          # eingebaute Selbstverwaltungs-Seite /auth/account (überschreibbar)
    forward_auth_enabled: bool = False    # /auth/forward + /auth/verify für Reverse-Proxy (Caddy/nginx/Traefik)
    https_mode: str = "warn"              # off | warn | force  — force = HTTP→HTTPS-Redirect;
                                          # warn = läuft auch OHNE Zertifikat (mit Warnhinweis im Panel)
    # Womit meldet man sich an? "username" | "email" | "both" (beides im selben Feld erlaubt)
    login_identifier: str = "both"
    allow_signup: bool = False            # Selbst-Registrierung (lokaler User+Passwort)
    signup_require_email: bool = True     # E-Mail bei der Registrierung Pflicht (eindeutig, s. login_identifier)
    signup_verify_email: bool = False     # Konto erst nach E-Mail-Bestätigung (Magic-Link) aktiv — braucht Mailer
    signup_invite_only: bool = False      # Registrierung nur mit gültigem Einladungs-Token
    signup_default_roles: list[str] = field(default_factory=list)  # Rollen für neue Selbst-Registrierte

    # --- Geteilte Ressourcen-Geheimnisse (ohne Benutzerkonto: eine PIN/Passphrase schützt einen Bereich) ---
    resource_locks_enabled: bool = False
    resource_unlock_ttl_hours: int = 12   # wie lange eine freigeschaltete Ressource offen bleibt
    resource_cookie: str = "tinysesam_runlock"

    # --- Magic-Link (Einmal-Login/-Zugang per E-Mail) ---
    magiclink_enabled: bool = False
    magiclink_ttl_min: int = 15           # Gültigkeit eines Einmal-Links

    # --- E-Mail-Versand (SMTP; per auth.set_mailer(fn) komplett überschreibbar) ---
    smtp_host: str = ""                   # leer + kein set_mailer → Versand deaktiviert
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""                   # Absender; leer = smtp_user
    smtp_starttls: bool = True            # 587 = STARTTLS; für 465 smtp_ssl=True setzen
    smtp_ssl: bool = False
    smtp_timeout: int = 15
    mail_subject_prefix: str = ""         # optionaler Betreff-Präfix, z.B. "[MeineApp] "

    # --- TOTP (2FA on-top zu Passwort/OIDC; Passkeys sind schon phishing-resistent) ---
    totp_enabled: bool = True             # User dürfen TOTP einrichten
    totp_required: bool = False           # TOTP nach Passwort/OIDC erzwingen (wenn eingerichtet: immer verlangt)
    recovery_code_count: int = 10         # Anzahl Einmal-Recovery-Codes je Erzeugung (verlorener Authenticator)

    # --- Passwort-Reset (Forgot-Password per E-Mail; braucht magiclink_enabled + Mailer) ---
    password_reset_enabled: bool = False

    # --- Faktor-Ketten (geordnete Kombinationen) ---
    # Globale Standard-Kette erfüllter Faktoren, die eine Sitzung vollständig macht, z.B.
    # ["oidc", "password"] oder ["password", "totp"]. Leer = klassisch (ein Erstfaktor + TOTP falls
    # eingerichtet). Pro Route überschreibbar: Depends(auth.require(factors=[...], strict=...)).
    # Faktornamen: password, pin, oidc, passkey, totp, magic. Der erste Faktor identifiziert den User.
    login_chain: list[str] = field(default_factory=list)
    login_chain_strict: bool = True       # Reihenfolge erzwingen (True) oder beliebig (False)

    # --- Step-up / per-Route-MFA (Sudo-Frische) ---
    # Guards mit mfa=True verlangen eine „frische" Faktor-Bestätigung. Frisch ist eine Sitzung
    # stepup_max_age_sec lang nach Login/Reauth; danach → /auth/reauth. 0 = nie ablaufen (nur „hat 2FA bestanden").
    stepup_max_age_sec: int = 900         # 15 min
    admin_require_mfa: bool = False        # Admin-Panel + require_admin verlangen zusätzlich Step-up-MFA

    # --- Sessions (server-side, revozierbar) ---
    session_cookie: str = "tinysesam_session"
    session_ttl_hours: int = 24 * 7       # TTL bei „Angemeldet bleiben" (persistentes Cookie)
    session_ttl_transient_hours: int = 12 # TTL ohne „Angemeldet bleiben" (Session-Cookie, endet beim Browser-Schließen)
    remember_me_enabled: bool = True      # „Angemeldet bleiben"-Checkbox anbieten (aus → immer persistent)
    cookie_secure: bool = True            # nur über HTTPS senden
    cookie_samesite: str = "lax"          # lax|strict|none
    cookie_path: str = "/"
    cookie_domain: str = ""               # leer = Host-only; für SSO über Subdomains z.B. ".example.com"

    # --- CSRF (Double-Submit-Cookie; zusätzlich zu SameSite=Lax) ---
    csrf_enabled: bool = True             # State-ändernde POSTs verlangen Token (Formular _csrf / Header X-CSRF-Token)
    csrf_cookie: str = "tinysesam_csrf"

    # --- LDAP / lldap (Passwort gegen Verzeichnis-Bind; zählt als Faktor 'password') ---
    ldap_enabled: bool = False
    ldap_url: str = ""                    # ldap://host:389 oder ldaps://host:636
    ldap_start_tls: bool = False
    ldap_user_dn_template: str = ""       # Direkt-Bind, z.B. "uid={username},ou=people,dc=example,dc=com" (lldap)
    ldap_bind_dn: str = ""                # ODER Service-Account für Search-then-Bind
    ldap_bind_password: str = ""
    ldap_user_base: str = ""              # Suchbasis (bei Search-then-Bind)
    ldap_user_filter: str = "(uid={username})"
    ldap_attr_email: str = "mail"
    ldap_attr_name: str = "cn"
    ldap_group_attr: str = "memberOf"     # Attribut mit Gruppen-Zugehörigkeit
    ldap_allowed_groups: list[str] = field(default_factory=list)  # leer = alle; sonst Gate (Teilstring-Match)
    ldap_auto_create: bool = True         # unbekannten LDAP-User lokal anlegen (ohne lokales Passwort)

    # --- OIDC ---
    oidc_name: str = "SSO"                # Anzeigename des Buttons
    oidc_issuer: str = ""                 # z.B. https://id.example.com  (…/.well-known/openid-configuration)
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_auto_create: bool = True         # unbekannten OIDC-User automatisch anlegen
    oidc_rp_logout: bool = False          # beim Abmelden auch den OIDC-Provider abmelden (end_session), optional
    oidc_group_claim: str = "groups"      # Claim mit den Gruppen
    oidc_allowed_groups: list[str] = field(default_factory=list)  # leer = alle erlaubt

    # --- SAML 2.0 (SP-Login gegen einen IdP: ADFS, Keycloak, Okta, Entra …) ---
    saml_enabled: bool = False
    saml_name: str = "SAML"               # Anzeigename des Buttons
    saml_sp_entity_id: str = ""           # eigene SP-Entity-ID; leer = base_url + /auth/saml/metadata
    saml_acs_url: str = ""                # Assertion Consumer Service; leer = base_url + /auth/saml/acs
    saml_idp_entity_id: str = ""
    saml_idp_sso_url: str = ""            # IdP Single-Sign-On-URL (Redirect-Binding)
    saml_idp_x509cert: str = ""           # IdP-Signaturzertifikat (PEM-Body, ohne BEGIN/END)
    saml_attr_username: str = ""          # Attribut mit dem Benutzernamen; leer = NameID
    saml_attr_email: str = "email"
    saml_attr_name: str = "displayName"
    saml_attr_groups: str = "groups"
    saml_allowed_groups: list[str] = field(default_factory=list)  # leer = alle
    saml_auto_create: bool = True

    # --- WebAuthn / Passkey ---
    rp_id: str = "localhost"              # Registrable Domain (z.B. paperlaiss.example.com) — OHNE Schema/Port
    rp_name: str = "TinySesam"            # Anzeigename der Relying Party
    origin: str = "http://localhost:8000" # exaktes Origin (Schema+Host+Port) des Browsers

    # --- App-Integration ---
    base_url: str = ""                    # öffentliche Base-URL (für OIDC-Callback); leer = aus Request abgeleitet
    login_path: str = "/auth/login"       # Login-Seite
    login_redirect: str = "/"             # Ziel nach erfolgreichem Login
    logout_redirect: str = "/auth/login"  # Ziel nach Logout

    # --- Härtung ---
    # Reverse-Proxies, deren X-Forwarded-For vertraut werden darf (sonst ist die echte Client-IP fälschbar).
    trusted_proxies: list[str] = field(default_factory=lambda: ["127.0.0.1/32", "::1/128"])
    # Prozessübergreifendes Rate-Limit über Redis (Multi-Worker); leer = In-Memory pro Prozess. Extra [redis].
    redis_url: str = ""                   # z.B. redis://localhost:6379/0
    # Hosts, auf die ?next= absolut zeigen darf (Open-Redirect-Schutz; leer = nur relative Pfade).
    trusted_redirect_hosts: list[str] = field(default_factory=list)
    # Feineinstellung (Versuche/Sperrzeit/Rate-Limit) liegt im Store und ist im Admin-Panel änderbar
    # (Defaults: tinysesam.security.SECURITY_DEFAULTS).

    @classmethod
    def oidc_gateway(cls, *, issuer, client_id, client_secret, base_url,
                     cookie_domain="", trusted_redirect_hosts=None, allowed_groups=None,
                     group_claim="groups", oidc_name="SSO", oidc_scopes="openid profile email",
                     db_path="tinysesam-gateway.db", https_mode="warn", session_ttl_hours=24 * 7,
                     trusted_proxies=None, **overrides):
        """Preset: TinySesam als reines **OIDC-Forward-Auth-Gateway** (Authelia-/oauth2-proxy-Stil).
        Alle anderen Methoden/Features aus, OIDC + Forward-Auth an. Läuft mit `pip install 'tinysesam[oidc]'`.
        Einzelne Felder via **overrides überschreibbar."""
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
            base_url=base_url, cookie_domain=cookie_domain,
            trusted_redirect_hosts=list(trusted_redirect_hosts or []),
            session_ttl_hours=session_ttl_hours, https_mode=https_mode,
            trusted_proxies=list(trusted_proxies or ["127.0.0.1/32", "::1/128"]),
        )
        base.update(overrides)
        return cls(**base)

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
        return cls(**base)

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
        return cls(**base)

    def enabled_methods(self) -> list[str]:
        m = []
        if self.password_enabled:
            m.append("password")
        if self.pin_enabled:
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
