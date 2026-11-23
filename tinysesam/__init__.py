"""TinySesam — small, reusable multi-method auth for FastAPI.

Methods (all can be enabled in parallel): password, passkey/WebAuthn, OIDC; TOTP as 2FA on top.
Roles are optional — whoever only needs "signed in or not" uses `require_user`.

TinySesam does **not update itself**. Whoever installs the library determines the version: via a
pinned Git tag or a release's wheel. See README,
section "Installation and updates".
"""
__version__ = "0.28.0"

from typing import TYPE_CHECKING

from .config import TinySesamConfig
from .errors import ConfigError, MailNotConfigured, MissingExtra, RoleError, StateError, TinySesamError
from .login_result import LoginResult
from .password_change_result import PasswordChangeResult

if TYPE_CHECKING:
    from .manager import TinySesam


def __getattr__(name: str):
    """`TinySesam` is imported on first use: the gate client (`tinysesam.gate_client`) runs in Flask or Django
    applications without FastAPI, and importing a submodule imports this package first."""
    if name == "TinySesam":
        from .manager import TinySesam
        globals()["TinySesam"] = TinySesam
        return TinySesam
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | {"TinySesam"})


def current_version() -> str:
    """Installed version — preferably the distribution metadata, which are also correct
    when TinySesam is a dependency inside a foreign app."""
    try:
        from importlib.metadata import version
        return version("tinysesam")
    except Exception:
        return __version__


__all__ = ["TinySesam", "TinySesamConfig", "LoginResult", "PasswordChangeResult", "current_version",
           "TinySesamError", "ConfigError", "MissingExtra", "MailNotConfigured", "StateError",
           "RoleError"]
