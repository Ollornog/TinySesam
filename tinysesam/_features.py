"""The feature registry (T-112): which building blocks a configuration switches on.

Each feature names the `TinySesamConfig` switch that turns it on, the modules of its building blocks, and the path
prefixes of its routes. `load_enabled` imports the building blocks of the features that are on when `TinySesam`
starts; a feature that is off is never imported — neither here nor through the router (its routes are registered
only when the switch is on) nor through `TinySesam` (its methods load on first use, and nothing calls them).
`tests/test_store_parts.py` starts an application with the features off and proves that none of these modules is
loaded and none of these routes exists.

Heavy optional libraries (python3-saml, authlib, webauthn, ldap3, qrcode) are imported inside their feature's
functions, never at the top of a module every start imports.
"""
from __future__ import annotations

import importlib

#: feature -> (switch in TinySesamConfig, building-block modules of the package, route path prefixes)
FEATURES: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "forward_auth": ("forward_auth_enabled", ("_routes_forward", "_manager_forward"),
                     ("/auth/forward", "/.tinysesam/callback", "/.tinysesam/start")),
    "qr_login": ("qr_login_enabled", ("_manager_qr",), ("/auth/qr",)),
    "resource_locks": ("resource_locks_enabled", ("_manager_resource",), ("/auth/resource/",)),
    "ldap": ("ldap_enabled", ("_manager_ldap",), ("/auth/ldap/",)),
    "saml": ("saml_enabled", ("_manager_saml", "saml_"), ("/auth/saml/",)),
    "oidc": ("oidc_enabled", ("oidc",), ("/auth/oidc/",)),
    "passkeys": ("passkey_enabled", ("webauthn_",), ("/auth/passkey/",)),
    "oauth": ("oauth_enabled", ("oauth", "_store_oauth"), ("/auth/oauth/", "/.well-known/oauth-authorization-server")),
    "approvals": ("approvals_enabled", ("approvals", "_store_approvals"), ("/auth/approvals",)),
    "magic_links": ("magiclink_enabled", ("_manager_links",), ("/auth/magic/",)),
}

#: Building blocks `load_enabled` imports up front — the package's own pure-Python modules. A module that needs an
#: optional library (oidc, saml_, webauthn_, oauth, approvals) stays with its own import path, which reports a
#: missing extra where it is used.
PRELOAD_PREFIXES = ("_manager_", "_routes_")


def enabled(cfg) -> list[str]:
    """The features this configuration switches on, in registry order."""
    return [name for name, (switch, _, _) in FEATURES.items() if getattr(cfg, switch, False)]


def load_enabled(cfg) -> list[str]:
    """Import the building blocks of every feature that is on; returns the module names it imported."""
    loaded = []
    for name in enabled(cfg):
        for module in FEATURES[name][1]:
            if module.startswith(PRELOAD_PREFIXES):
                importlib.import_module(f"{__package__}.{module}")
                loaded.append(module)
    return loaded
