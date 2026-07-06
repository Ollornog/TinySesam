"""Konfiguration für TinySesam. Die einbindende App füllt TinySesamConfig und übergibt es an TinySesam()."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class TinySesamConfig:
    # --- Store ---
    db_path: str = "tinysesam.db"

    # --- Aktive Login-Methoden (alle parallel möglich) ---
    password_enabled: bool = True
    passkey_enabled: bool = True          # WebAuthn / Passkeys (passwortlos)
    oidc_enabled: bool = False            # externer IdProvider (PocketID …)
    apikey_enabled: bool = True           # Zugang per API-Key (maschinell/Daemons, an User/Service-Account)
    admin_enabled: bool = True            # eingebautes Admin-Panel unter /auth/admin (nur für Admins)
    allow_signup: bool = False            # Selbst-Registrierung (lokaler User+Passwort)

    # --- TOTP (2FA on-top zu Passwort/OIDC; Passkeys sind schon phishing-resistent) ---
    totp_enabled: bool = True             # User dürfen TOTP einrichten
    totp_required: bool = False           # TOTP nach Passwort/OIDC erzwingen (wenn eingerichtet: immer verlangt)

    # --- Sessions (server-side, revozierbar) ---
    session_cookie: str = "tinysesam_session"
    session_ttl_hours: int = 24 * 7
    cookie_secure: bool = True            # nur über HTTPS senden
    cookie_samesite: str = "lax"          # lax|strict|none
    cookie_path: str = "/"

    # --- OIDC ---
    oidc_name: str = "SSO"                # Anzeigename des Buttons
    oidc_issuer: str = ""                 # z.B. https://id.example.com  (…/.well-known/openid-configuration)
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_auto_create: bool = True         # unbekannten OIDC-User automatisch anlegen
    oidc_group_claim: str = "groups"      # Claim mit den Gruppen
    oidc_allowed_groups: list[str] = field(default_factory=list)  # leer = alle erlaubt

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
    # Feineinstellung (Versuche/Sperrzeit/Rate-Limit) liegt im Store und ist im Admin-Panel änderbar
    # (Defaults: tinysesam.security.SECURITY_DEFAULTS).

    def enabled_methods(self) -> list[str]:
        m = []
        if self.password_enabled:
            m.append("password")
        if self.passkey_enabled:
            m.append("passkey")
        if self.oidc_enabled and self.oidc_issuer and self.oidc_client_id:
            m.append("oidc")
        return m
