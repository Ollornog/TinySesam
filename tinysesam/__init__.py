"""TinySesam — kleines, wiederverwendbares Multi-Methoden-Auth für FastAPI.

Methoden (alle parallel aktivierbar): Passwort, Passkey/WebAuthn, OIDC; TOTP als 2FA on-top.
Rollen optional (paperlaiss nutzt nur require_user = eingeloggt/nicht).
"""
from .config import TinySesamConfig
from .manager import TinySesam

__all__ = ["TinySesam", "TinySesamConfig"]
__version__ = "0.1.0"
