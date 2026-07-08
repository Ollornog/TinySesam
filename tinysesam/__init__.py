"""TinySesam — kleines, wiederverwendbares Multi-Methoden-Auth für FastAPI.

Methoden (alle parallel aktivierbar): Passwort, Passkey/WebAuthn, OIDC; TOTP als 2FA on-top.
Rollen optional (paperlaiss nutzt nur require_user = eingeloggt/nicht).
"""
__version__ = "0.7.0"

from .config import TinySesamConfig
from .manager import TinySesam
from .updater import current_version, latest_version, update_available, self_update

__all__ = ["TinySesam", "TinySesamConfig",
           "current_version", "latest_version", "update_available", "self_update"]
