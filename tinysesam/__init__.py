"""TinySesam — kleines, wiederverwendbares Multi-Methoden-Auth für FastAPI.

Methoden (alle parallel aktivierbar): Passwort, Passkey/WebAuthn, OIDC; TOTP als 2FA on-top.
Rollen sind optional — wer nur „eingeloggt oder nicht" braucht, nimmt `require_user`.

TinySesam aktualisiert sich **nicht selbst**. Die Version bestimmt, wer die Bibliothek
installiert: über einen gepinnten Git-Tag bzw. das Wheel eines Releases. Siehe README,
Abschnitt „Installation und Updates".
"""
__version__ = "0.13.1"

from .config import TinySesamConfig
from .manager import TinySesam


def current_version() -> str:
    """Installierte Version — bevorzugt die Distribution-Metadaten, die auch dann stimmen,
    wenn TinySesam als Abhängigkeit in einer fremden App steckt."""
    try:
        from importlib.metadata import version
        return version("tinysesam")
    except Exception:
        return __version__


__all__ = ["TinySesam", "TinySesamConfig", "current_version"]
