"""`tinysesam diagnose` (T-79): a report the operator reads, checks and sends themselves — instead of telemetry.

TinySesam never phones home, not even as an opt-in (decision in T-79). When something goes wrong, the operator runs
`python -m tinysesam diagnose` (library) or `python -m tinysesam.gateway diagnose` (gateway image) and gets a
Markdown report plus a prefilled link to the bug form. Nothing is sent: the command makes **no network request**,
writes nothing and does not construct `TinySesam` (that would create keys and seed the database).

What the report holds:

* version, Python, operating system family, mode, installed extras;
* the **shape** of the configuration: which fields differ from the default. Switches and numbers are shown, a choice
  from a fixed set only when it is one of the known values, everything else as a placeholder (`<url-1>`,
  `<host-2>`) or as `<set>` / `<3 entries>`. Secrets are only ever `<set>`;
* the built-in checks: `config_check` (errors, warnings), proxy headers, the clock, the database schema, where the
  vault key lies, gate token and JWKS;
* the latest warnings and errors of the security log (`--log`), redacted.

Redaction works in layers, so that one gap does not leak (`Redactor`): every configured value outside the known-safe
set is registered with the pieces derived from it (host of a URL, domain of an address, parts of a DN) and replaced
wherever it appears — case-insensitively. After that, patterns catch what no configuration knows: URLs, addresses,
IPs, host names, quoted values; in log lines also every `key=value` outside a short safe list, everything after
`": "`, the contents of parentheses and paths.

Every configuration field is classified in `FIELDS`. A field without a class is shown as redacted — and
`tests/test_diagnose.py` turns red, so a new field gets a deliberate decision.
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import importlib
import importlib.util
import ipaddress
import os
import platform
import re
import sqlite3
import stat
import sys
import time
from typing import Any, Callable, Optional
from urllib.parse import quote, urlencode, urlsplit

# --- classification of the configuration fields --------------------------------------------------------------------

#: A number or switch: shown as it is (a string in such a field counts as redacted).
SHOW = "show"
#: A free value (host, URL, name, path, HTML, mapping …): a placeholder or `<set>` / `<N entries>`.
REDACT = "redact"
#: A secret: only ever `<set>`, never a placeholder, never a length.
SECRET = "secret"
#: Sign-in method names (`login_chain`, `stepup_methods`): known names shown, anything else `<custom>`.
METHODS = "methods"

#: The method names a chain or step-up list may contain; anything else is shown as `<custom>`.
METHOD_NAMES = frozenset({"password", "passkey", "pin", "totp", "oidc", "saml", "ldap", "magiclink", "qr",
                          "recovery", "email", "webauthn"})


def _one_of(*values: str) -> frozenset:
    """A field with a fixed set of values: one of them is shown, anything else is `<custom>`."""
    return frozenset(values)


#: Every field of `TinySesamConfig`, classified. `tests/test_diagnose.py` keeps this complete.
FIELDS: dict[str, Any] = {
    "db_path": REDACT,
    "lang": _one_of("en", "de"),
    "brand_css": REDACT,
    "brand_head": REDACT,
    "c22_stylesheet": REDACT,
    "brand_icon": REDACT,
    "brand_icon_title": REDACT,
    "brand_backgrounds": REDACT,
    "brand_background_seconds": SHOW,
    "brand_background_credit_text": REDACT,
    "brand_background_credit_url": REDACT,
    "brand_header": REDACT,
    "brand_footer": REDACT,
    "topbar_enabled": SHOW,
    "topbar_links": REDACT,
    "topbar_menu_links": REDACT,
    "admin_implies_roles": SHOW,
    "group_match": _one_of("exact", "substring"),
    "available_roles": REDACT,
    "role_levels": REDACT,
    "oidc_group_role_map": REDACT,
    "saml_group_role_map": REDACT,
    "ldap_group_role_map": REDACT,
    "password_enabled": SHOW,
    "password_blocklist_file": REDACT,
    "passkey_enabled": SHOW,
    "passkey_user_verification": _one_of("required", "preferred", "discouraged"),
    "pin_enabled": SHOW,
    "pin_login": SHOW,
    "pin_min_length": SHOW,
    "stepup_methods": METHODS,
    "stepup_strict": SHOW,
    "oidc_enabled": SHOW,
    "oidc_callback_path": REDACT,
    "apikey_enabled": SHOW,
    "apikey_default_days": SHOW,
    "apikey_allow_unlimited": SHOW,
    "app_password_default_days": SHOW,
    "app_password_allow_unlimited": SHOW,
    "admin_enabled": SHOW,
    "admin_path": REDACT,
    "admin_ui_enabled": SHOW,
    "account_enabled": SHOW,
    "forward_auth_enabled": SHOW,
    "forward_headers": REDACT,
    "gate_token_enabled": SHOW,
    "gate_token_ttl_sec": SHOW,
    "gate_key_file": REDACT,
    "approval_key_file": REDACT,
    "forward_login": _one_of("page", "direct"),
    "forward_logout": _one_of("all", "app", "ask"),
    "forward_logged_out_sec": SHOW,
    "forward_apps": REDACT,
    "forward_frame_default": REDACT,
    "gate_cookie_name": REDACT,
    "gate_link_enabled": SHOW,
    "oauth_enabled": SHOW,
    "oauth_resources": REDACT,
    "oauth_access_token_ttl_sec": SHOW,
    "oauth_refresh_idle_days": SHOW,
    "oauth_refresh_max_days": SHOW,
    "oauth_refresh_grace_sec": SHOW,
    "oauth_pepper_file": REDACT,
    "oauth_service_clients": SHOW,
    "oauth_service_token_ttl_sec": SHOW,
    "oauth_service_key_days": SHOW,
    "oauth_pairing_minutes": SHOW,
    "https_mode": _one_of("off", "warn", "force"),
    "hsts": REDACT,
    "login_identifier": _one_of("username", "email", "both"),
    "admin_identifiers": REDACT,
    "admin_claim_ttl_min": SHOW,
    "admin_claim_token_file": REDACT,
    "demo_mode": SHOW,
    "demo_password": SECRET,
    "demo_pin": SECRET,
    "allow_signup": SHOW,
    "signup_require_email": SHOW,
    "signup_verify_email": SHOW,
    "signup_invite_only": SHOW,
    "signup_default_roles": REDACT,
    "resource_locks_enabled": SHOW,
    "resource_unlock_ttl_hours": SHOW,
    "resource_cookie": REDACT,
    "magiclink_enabled": SHOW,
    "magiclink_self_request": SHOW,
    "magiclink_ttl_min": SHOW,
    "invite_ttl_min": SHOW,
    "signin_link_max_ttl_min": SHOW,
    "magiclink_require_second_factor": SHOW,
    "magiclink_first_login_only": SHOW,
    "qr_login_enabled": SHOW,
    "qr_login_ttl_sec": SHOW,
    "qr_login_require_second_factor": SHOW,
    "self_service_email_change": SHOW,
    "self_service_username_change": SHOW,
    "email_change_ttl_min": SHOW,
    "smtp_host": REDACT,
    "smtp_port": SHOW,
    "smtp_user": REDACT,
    "smtp_password": SECRET,
    "smtp_from": REDACT,
    "smtp_starttls": SHOW,
    "smtp_ssl": SHOW,
    "smtp_timeout": SHOW,
    "smtp_ca_file": REDACT,
    "mail_subject_prefix": REDACT,
    "notify_login_failures": SHOW,
    "notify_new_access": SHOW,
    "totp_enabled": SHOW,
    "totp_window": _one_of("previous", "current", "previous_and_next"),
    "secrets_key_file": REDACT,
    "totp_required": SHOW,
    "recovery_code_count": SHOW,
    "recovery_codes_enabled": SHOW,
    "totp_app_hint": REDACT,
    "password_reset_enabled": SHOW,
    "login_chain": METHODS,
    "mfa_enrollment": _one_of("first_login", "grace", "strict"),
    "mfa_enrollment_grace_days": SHOW,
    "login_chain_strict": SHOW,
    "stepup_max_age_sec": SHOW,
    "admin_require_mfa": SHOW,
    "admin_password_must_change": SHOW,
    "admin_delegates": REDACT,
    "approvals_enabled": SHOW,
    "approval_pending_sec": SHOW,
    "approval_open_per_account": SHOW,
    "approval_open_per_token": SHOW,
    "approval_requests_per_hour": SHOW,
    "approval_reject_limit": SHOW,
    "approval_pickup_sec": SHOW,
    "approval_token_ttl_sec": SHOW,
    "approval_app_requests_per_hour": SHOW,
    "apps": REDACT,
    "session_cookie": REDACT,
    "session_ttl_hours": SHOW,
    "session_ttl_transient_hours": SHOW,
    "remember_me_enabled": SHOW,
    "session_idle_minutes": SHOW,
    "session_idle_minutes_remember": SHOW,
    "session_rotation_grace_sec": SHOW,
    "cookie_secure": SHOW,
    "cookie_samesite": _one_of("lax", "strict", "none"),
    "cookie_path": REDACT,
    "cookie_domain": REDACT,
    "cookie_host_prefix": SHOW,
    "cookie_prefix": REDACT,
    "csp": _one_of("strict", "off"),
    "csp_report": SHOW,
    "csrf_enabled": SHOW,
    "csrf_cookie": REDACT,
    "csrf_origin_check": SHOW,
    "federation_require_stable_id": SHOW,
    "federation_name_binding_days": SHOW,
    "ldap_enabled": SHOW,
    "ldap_url": REDACT,
    "ldap_start_tls": SHOW,
    "ldap_tls_verify": SHOW,
    "ldap_tls_ca_file": REDACT,
    "ldap_allow_plaintext": SHOW,
    "ldap_user_dn_template": REDACT,
    "ldap_bind_dn": REDACT,
    "ldap_bind_password": SECRET,
    "ldap_user_base": REDACT,
    "ldap_user_filter": REDACT,
    "ldap_attr_id": REDACT,
    "ldap_attr_email": REDACT,
    "ldap_email_trusted": SHOW,
    "ldap_attr_email_verified": REDACT,
    "ldap_attr_name": REDACT,
    "ldap_group_attr": REDACT,
    "ldap_allowed_groups": REDACT,
    "ldap_auto_create": SHOW,
    "oidc_name": REDACT,
    "oidc_issuer": REDACT,
    "oidc_client_id": REDACT,
    "oidc_client_secret": SECRET,
    "oidc_scopes": REDACT,
    "oidc_auto_create": SHOW,
    "oidc_email_verified_default": SHOW,
    "oidc_rp_logout": SHOW,
    "oidc_group_claim": REDACT,
    "oidc_allowed_groups": REDACT,
    "oidc_clients": REDACT,
    "oidc_revalidate_minutes": SHOW,
    "oidc_reauth_check": SHOW,
    "oidc_session_refresh_minutes": SHOW,
    "oidc_session_max_unverified_hours": SHOW,
    "oidc_apikey_confirm_days": SHOW,
    "saml_enabled": SHOW,
    "saml_name": REDACT,
    "saml_sp_entity_id": REDACT,
    "saml_acs_url": REDACT,
    "saml_idp_entity_id": REDACT,
    "saml_idp_sso_url": REDACT,
    "saml_idp_x509cert": SECRET,
    "saml_attr_username": REDACT,
    "saml_attr_email": REDACT,
    "saml_email_trusted": SHOW,
    "saml_attr_email_verified": REDACT,
    "federation_email_confirm": SHOW,
    "saml_attr_name": REDACT,
    "saml_attr_id": REDACT,
    "saml_attr_groups": REDACT,
    "saml_allowed_groups": REDACT,
    "saml_auto_create": SHOW,
    "rp_id": REDACT,
    "rp_name": REDACT,
    "gate_brand": REDACT,
    "origin": REDACT,
    "base_url": REDACT,
    "login_path": REDACT,
    "login_redirect": REDACT,
    "logout_redirect": REDACT,
    "trusted_proxies": REDACT,
    "redis_url": SECRET,      # may carry a password: redis://:secret@host/0
    "trusted_redirect_hosts": REDACT,
    "security_log": REDACT,
    "audit_retention_days": SHOW,
    "audit_ip_pseudonymize": SHOW,
}

#: Extras of `pyproject.toml` → the distributions they install.
EXTRAS: dict[str, tuple[str, ...]] = {
    "argon2": ("argon2-cffi",),
    "qr": ("qrcode",),
    "oidc": ("httpx", "authlib"),
    "passkey": ("webauthn",),
    "ldap": ("ldap3",),
    "redis": ("redis",),
    "saml": ("python3-saml",),
    "gateway": ("httpx", "authlib", "uvicorn"),
    "services": ("joserfc",),
}
#: Distributions whose version helps to reproduce a bug.
PACKAGES = ("fastapi", "starlette", "cryptography", "uvicorn", "httpx", "authlib", "webauthn", "ldap3",
            "python3-saml", "redis", "argon2-cffi", "joserfc")

ISSUE_URL = "https://github.com/Ollornog/TinySesam/issues/new"
#: GitHub refuses longer addresses; below this the link carries everything, above it sections go out as a note.
LINK_MAX = 8000
#: The sections of the report — the same ids as the fields of `.github/ISSUE_TEMPLATE/bug.yml`.
SECTIONS = ("environment", "configuration", "checks", "log")
TOO_LONG = "(too long for the link: paste this section from the report printed in the terminal)"


# --- redaction --------------------------------------------------------------------------------------------------------

_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>()\]]+")
_EMAIL = re.compile(r"[^\s@'\"<>(),;:=\[\]]+@[^\s@'\"<>(),;:\[\]]+")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?(?![0-9A-Za-z:])")
_HOST = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w-])")
_QUOTED = re.compile(r"'([^'\n]*)'|\"([^\"\n]*)\"")
_PLACEHOLDER = re.compile(r"^<[a-z]+(?:-\d+)?>$")
#: Dotted names that are code, not hosts: module and attribute paths of this package and its tools, file names.
_CODE_PREFIXES = ("tinysesam.", "auth.", "cfg.", "config.", "uvicorn.", "os.", "request.", "store.", "security.",
                  "self.", "sys.", "app.", "router.")
_CODE_SUFFIXES = (".py", ".md", ".yml", ".yaml", ".json", ".css", ".html", ".toml", ".txt", ".conf")
#: `key=value` in a log line: the value stays only for these keys, and only if it looks like a code word.
_LOG_SAFE_KEYS = frozenset({"method", "reason", "event", "disposition", "directive", "remaining", "error", "unban",
                            "user_id", "purpose", "sec-fetch-site", "authenticated"})
_CODE_WORD = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
_LOG_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:,\d{3})?) (WARNING|ERROR|CRITICAL) (.*)$")


def _kind(value: str, field_kind: str) -> str:
    """What a value looks like — it names the placeholder."""
    if field_kind == SECRET:
        return "secret"
    if "://" in value:
        return "url"
    if "@" in value:
        return "email"
    try:
        ipaddress.ip_network(value, strict=False)
        return "ip"
    except ValueError:
        pass    # not an address or network: the shapes below decide
    if value.startswith("/") or os.sep in value:
        return "path"
    if _HOST.fullmatch(value.strip("*.")):
        return "host"
    return "value"


class Redactor:
    """Replaces every registered value and every pattern by a stable placeholder (`<host-1>` stays `<host-1>`)."""

    def __init__(self) -> None:
        self._known: dict[str, str] = {}       # lower-case value → kind
        self._names: dict[str, str] = {}       # lower-case value → placeholder
        self._counts: dict[str, int] = {}
        self._pattern: Optional[re.Pattern] = None
        self.safe_words: set[str] = set()

    # -- registration --
    def register(self, value: Any, field_kind: str = REDACT) -> None:
        """Register a configured value (strings inside lists and mappings too, keys included)."""
        if isinstance(value, str):
            self._add(value, field_kind)
        elif isinstance(value, dict):
            for k, v in value.items():
                self.register(k, field_kind)
                nested = SECRET if isinstance(k, str) and any(w in k.lower() for w in ("secret", "password", "key",
                                                                                         "token", "cert")) else field_kind
                self.register(v, nested)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for v in value:
                self.register(v, field_kind)

    def _add(self, value: str, field_kind: str) -> None:
        value = value.strip()
        if len(value) < 3 or value.lower() in self.safe_words:
            return
        kind = _kind(value, field_kind)
        self._put(value, kind)
        if field_kind == SECRET:
            return
        stripped = value.strip("*. ")
        if stripped != value:
            self._put(stripped, kind)
        if kind == "url":
            try:
                parts = urlsplit(value)
                if parts.netloc:
                    self._put(parts.netloc.rsplit("@", 1)[-1], "host")
                if parts.hostname:
                    self._put(parts.hostname, "host")
                if parts.username:
                    self._put(parts.username, "value")
                if parts.password:
                    self._put(parts.password, "secret")
                for segment in (parts.path or "").split("/"):
                    if len(segment) >= 8:
                        self._put(segment, "value")
                if parts.path and len(parts.path) > 1:
                    self._put(parts.path, "path")
            except ValueError:
                # A malformed URL (unbalanced IPv6 brackets) has no parts to take apart; the whole value is registered
                # above and the patterns of `text` still catch what looks like a host.
                return
        elif kind == "email":
            local, _, domain = value.rpartition("@")
            self._put(local, "user")
            self._put(domain, "host")
        if "=" in value and "," in value:          # an LDAP DN or filter: its parts on their own
            for piece in re.split(r"[,()&|]", value):
                _k, _, v = piece.partition("=")
                if v and "{" not in v:
                    self._put(v, "value")
        # A comma-separated list in one string: its items on their own. Not split at spaces — the words of a credit
        # text or the scopes `openid profile email` would black out the same words everywhere in the report.
        for piece in value.split(","):
            piece = piece.strip()
            if piece != value and piece and not any(ch.isspace() for ch in piece):
                self._add(piece, field_kind)

    def _put(self, value: str, kind: str) -> None:
        value = value.strip()
        low = value.lower()
        if len(value) < 3 or low in self.safe_words or _PLACEHOLDER.match(value):
            return
        if low not in self._known:
            self._known[low] = kind
            self._pattern = None

    # -- placeholders --
    def name(self, value: str, kind: str) -> str:
        low = value.lower()
        if low not in self._names:
            if kind == "secret":
                self._names[low] = "<secret>"
            else:
                self._counts[kind] = self._counts.get(kind, 0) + 1
                self._names[low] = f"<{kind}-{self._counts[kind]}>"
        return self._names[low]

    def placeholder(self, value: str) -> Optional[str]:
        """The placeholder of a whole registered value — None if it is not registered as one piece."""
        low = value.strip().lower()
        if low in self._known:
            return self.name(low, self._known[low])
        return None

    def _known_pattern(self) -> Optional[re.Pattern]:
        if self._pattern is None and self._known:
            parts = []
            for low in sorted(self._known, key=len, reverse=True):
                escaped = re.escape(low)
                # A short value only as a whole word: `admin` must not eat `admin_identifiers`.
                parts.append(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])" if len(low) < 6 else escaped)
            self._pattern = re.compile("|".join(parts), re.IGNORECASE)
        return self._pattern

    # -- text --
    def text(self, text: str) -> str:
        """Known values, then URLs, addresses, IPs, host names and quoted values."""
        pattern = self._known_pattern()
        if pattern is not None:
            text = pattern.sub(lambda m: self.name(m.group(0), self._known[m.group(0).lower()]), text)
        text = _URL.sub(lambda m: self.name(m.group(0), "url"), text)
        text = _EMAIL.sub(lambda m: self.name(m.group(0), "email"), text)
        text = _IPV4.sub(lambda m: self.name(m.group(0), "ip"), text)
        text = _IPV6.sub(self._ipv6, text)
        text = _HOST.sub(self._host, text)
        return _QUOTED.sub(self._quoted, text)

    def _ipv6(self, m: re.Match) -> str:
        try:
            ipaddress.ip_network(m.group(0), strict=False)
        except ValueError:
            return m.group(0)
        return self.name(m.group(0), "ip")

    def _host(self, m: re.Match) -> str:
        word = m.group(0)
        low = word.lower()
        if low.startswith(_CODE_PREFIXES) or low.endswith(_CODE_SUFFIXES):
            return word
        return self.name(word, "host")

    def _quoted(self, m: re.Match) -> str:
        inner = m.group(1) if m.group(1) is not None else m.group(2)
        quote_char = m.group(0)[0]
        if (not inner or inner.lower() in self.safe_words or _PLACEHOLDER.match(inner)
                or re.fullmatch(r"[\d.]+", inner)):
            return m.group(0)
        return f"{quote_char}<value>{quote_char}"

    def log_line(self, message: str) -> str:
        """A security log message: `key=value` outside the safe list, text after `": "`, parentheses and paths go —
        before the known values, so that a configured word (`user` as a header key) cannot hide a key."""
        message = re.sub(r"([A-Za-z_][\w-]*)=(\S+)", self._log_pair, message)
        head, sep, _rest = message.partition(": ")
        if sep:
            message = head + ": <redacted>"
        message = re.sub(r"\([^()]*\)", "(<redacted>)", message)
        message = re.sub(r"(?<!\S)/\S*", "<path>", message)
        return self.text(message)

    def _log_pair(self, m: re.Match) -> str:
        key, value = m.group(1), m.group(2)
        if key.lower() in _LOG_SAFE_KEYS and _CODE_WORD.match(value) and not _IPV4.search(value):
            return m.group(0)
        return f"{key}=<redacted>"


# --- report -----------------------------------------------------------------------------------------------------------

def _default(f: dataclasses.Field) -> Any:
    if f.default is not dataclasses.MISSING:
        return f.default
    if f.default_factory is not dataclasses.MISSING:          # type: ignore[misc]
        return f.default_factory()                             # type: ignore[misc]
    return dataclasses.MISSING


def _count(value: Any) -> str:
    n = len(value)
    return f"<{n} {'entry' if n == 1 else 'entries'}>"


def _methods(value: Any) -> str:
    if not isinstance(value, (list, tuple)):
        return "<custom>"
    out = []
    for step in value:
        if isinstance(step, str) and all(p.strip() in METHOD_NAMES for p in step.split("|")):
            out.append(step)
        else:
            out.append("<custom>")
    return "[" + ", ".join(out) + "]"


def _shown(value: Any, cls: Any, red: Redactor) -> str:
    """How a value differing from the default appears in the report."""
    if cls == SHOW and isinstance(value, (bool, int, float)) and not isinstance(value, str):
        return repr(value)
    if isinstance(cls, frozenset):
        return repr(value) if isinstance(value, str) and value in cls else "<custom>"
    if cls == METHODS:
        return _methods(value)
    if cls == SECRET:
        return "<set>" if value else "<empty>"
    if callable(value) and not isinstance(value, str):
        return "<callable>"
    if isinstance(value, (list, tuple, dict, set, frozenset)):
        return _count(value)
    if isinstance(value, str):
        if not value:
            return "<empty>"
        return red.placeholder(value) or "<set>"
    if isinstance(value, (bool, int, float)) or value is None:
        return repr(value)
    return "<set>"


def _safe_words(cfg: Any) -> set[str]:
    """Words that may stay in the report: field names, the known choices, method names, placeholders' kinds."""
    words = {f.name.lower() for f in dataclasses.fields(cfg)} if cfg is not None else set()
    for cls in FIELDS.values():
        if isinstance(cls, frozenset):
            words |= set(cls)
    return words | set(METHOD_NAMES)


def _redactor(cfg: Any) -> Redactor:
    red = Redactor()
    red.safe_words = _safe_words(cfg)
    if cfg is None:
        return red
    for f in dataclasses.fields(cfg):
        value = getattr(cfg, f.name, None)
        cls = FIELDS.get(f.name, REDACT)
        if cls == SHOW and isinstance(value, (bool, int, float)):
            continue
        if isinstance(cls, frozenset) and isinstance(value, str) and value in cls:
            continue
        if value == _default(f) and cls != SECRET:
            continue
        red.register(value, SECRET if cls == SECRET else REDACT)
    return red


def _environment(mode: str) -> list[str]:
    from importlib.metadata import PackageNotFoundError, version
    from . import current_version

    def dist(name: str) -> Optional[str]:
        try:
            return version(name)
        except PackageNotFoundError:
            return None
        except Exception:    # broken metadata must not end the report
            return None

    present = {name: dist(name) for name in set(PACKAGES) | {d for ds in EXTRAS.values() for d in ds}}
    extras = [e for e, ds in EXTRAS.items() if all(present.get(d) for d in ds)]
    missing = [e for e in EXTRAS if e not in extras]
    container = any(os.path.exists(p) for p in ("/.dockerenv", "/run/.containerenv"))
    lines = [
        f"- TinySesam: {current_version()}",
        f"- Mode: {mode}",
        f"- Python: {platform.python_version()} ({platform.python_implementation()})",
        f"- OS: {platform.system() or 'unknown'} {platform.machine() or ''}".rstrip()
        + f", container: {'yes' if container else 'no'}",
        f"- Extras installed: {', '.join(extras) or 'none'}" + (f" (not installed: {', '.join(missing)})"
                                                               if missing else ""),
        "- Packages: " + (", ".join(f"{n} {present[n]}" for n in PACKAGES if present.get(n)) or "none found"),
    ]
    return lines


def _configuration(cfg: Any, source: str, red: Redactor, load_error: str) -> list[str]:
    lines = [f"- Source: {source}"]
    if load_error:
        lines.append(f"- Could not be loaded: {red.text(load_error)}")
    if cfg is None:
        return lines
    changed = []
    unclassified = []
    for f in dataclasses.fields(cfg):
        value = getattr(cfg, f.name, None)
        cls = FIELDS.get(f.name)
        if cls is None:
            unclassified.append(f.name)
            cls = REDACT
        try:
            differs = value != _default(f)
        except Exception:
            differs = True
        if differs:
            changed.append(f"  - `{f.name}` = {_shown(value, cls, red)}")
    lines.append(f"- Fields that differ from the default: {len(changed)}")
    lines += changed
    if unclassified:
        lines.append(f"- Fields this version cannot classify (shown redacted): {len(unclassified)}")
    return lines


def _readonly(db_path: str) -> Optional[sqlite3.Connection]:
    """The database read-only — never created, never migrated, never written."""
    if not db_path or not os.path.isfile(db_path):
        return None
    try:
        # Without a -wal file the database is checkpointed and closed: `immutable` reads it without creating -wal and
        # -shm. With one, a service is running (or crashed): read through the WAL like any reader, in `ro` mode.
        live = os.path.exists(db_path + "-wal")
        uri = "file:" + quote(os.path.abspath(db_path)) + ("?mode=ro" if live else "?mode=ro&immutable=1")
        return sqlite3.connect(uri, uri=True, timeout=1)
    except sqlite3.Error:
        return None


def _scalar(db: Optional[sqlite3.Connection], sql: str, args: tuple = ()) -> Any:
    if db is None:
        return None
    try:
        row = db.execute(sql, args).fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None


def _key_file_state(path: str, db_path: str) -> str:
    beside = bool(db_path) and os.path.dirname(os.path.abspath(path)) == os.path.dirname(os.path.abspath(db_path))
    if not os.path.exists(path):
        return f"beside the database: {'yes' if beside else 'no'}, file missing (created on the first start)"
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        private = "yes" if mode & 0o077 == 0 else "no"
    except OSError:
        private = "unknown"
    return f"beside the database: {'yes' if beside else 'no'}, present, readable by owner only: {private}"


def _checks(cfg: Any, mode: str, db_path: str, red: Redactor, log_lines: list[str]) -> list[str]:
    from .store import Store

    lines: list[str] = []
    if cfg is not None:
        try:
            probe = copy.copy(cfg)
            probe.lang = "en"                     # the report is English, whatever the pages speak
            errors, warnings = probe._findings()
            lines.append(f"- config_check: {len(errors)} error(s), {len(warnings)} warning(s)")
            lines += [f"  - error: {red.text(m)}" for m in errors]
            lines += [f"  - warning: {red.text(m)}" for m in warnings]
        except Exception as e:
            lines.append(f"- config_check: raised {type(e).__name__}")
        proxies = list(getattr(cfg, "trusted_proxies", None) or [])
        default = proxies == ["127.0.0.1/32", "::1/128"]
        wide = any(p in ("0.0.0.0/0", "::/0") for p in proxies if isinstance(p, str))
        lines.append("- Proxy: trusted_proxies " + ("is the default (loopback only)" if default
                                                     else f"has {len(proxies)} entr{'y' if len(proxies) == 1 else 'ies'}")
                     + (", one of them trusts every address (0.0.0.0/0 or ::/0)" if wide else ""))
        if default and mode == "gateway":
            lines.append("  - hint: in a container the proxy is not 127.0.0.1 — enter the proxy's network")
    else:
        lines.append("- config_check: no configuration given")
    lines.append("  - hint: start uvicorn with --no-proxy-headers (the gateway does it itself), so TinySesam reads "
                 "X-Forwarded-For against trusted_proxies")
    if any("already applied by the server" in line for line in log_lines):
        lines.append("  - the security log shows uvicorn applied X-Forwarded-For itself (--no-proxy-headers missing)")
    if any("is ignored: the peer is not in trusted_proxies" in line for line in log_lines):
        lines.append("  - the security log shows X-Forwarded-For from a peer outside trusted_proxies")

    db = _readonly(db_path)
    now = int(time.time())
    clock = []
    newest = _scalar(db, "SELECT MAX(ts) FROM audit")
    if isinstance(newest, int):
        ahead = newest - now
        clock.append("newest audit entry is " + (f"{ahead} s in the future — the clock went back" if ahead > 60
                                                 else "not in the future (ok)"))
    if os.path.exists("/run/systemd/timesync/synchronized"):
        clock.append("systemd-timesyncd reports synchronised")
    lines.append("- Clock: " + ("; ".join(clock) if clock else "not checkable without network or database"))

    if db is None:
        lines.append("- Database: " + ("not found" if db_path else "no path given") + " (schema not checked)")
    else:
        present = _scalar(db, "PRAGMA user_version")
        expected = Store.SCHEMA_VERSION
        if present == expected:
            state = "current"
        elif isinstance(present, int) and present < expected:
            state = "older — the next start migrates it (take a backup first)"
        else:
            state = "NEWER than this version — written by a later TinySesam"
        lines.append(f"- Database schema: {present} (this version: {expected}) — {state}")

    from . import keys as K
    key_file = getattr(cfg, "secrets_key_file", "") if cfg is not None else ""
    if os.environ.get(K.ENV[K.VAULT]):
        vault = "from the environment, beside the database: no"
    elif key_file:
        vault = "from secrets_key_file, " + _key_file_state(key_file, db_path)
    elif db_path:
        vault = "<db>.key, " + _key_file_state(db_path + ".key", db_path)
    else:
        vault = "unknown (no database path)"
    lines.append(f"- Vault key: {vault}")

    if cfg is not None:
        gate_on = bool(getattr(cfg, "gate_token_enabled", False))
        gate_file = getattr(cfg, "gate_key_file", "")
        if os.environ.get(K.ENV[K.GATE]):
            source = "environment"
        elif gate_file:
            source = "gate_key_file (" + ("present" if os.path.exists(gate_file) else "file missing") + ")"
        else:
            stored = _scalar(db, "SELECT COUNT(*) FROM key_material WHERE purpose=?", (K.GATE,))
            source = "database" if stored else "none yet (created on the first start)"
        lines.append(f"- Gate token: {'on' if gate_on else 'off'}, JWKS at /auth/gate/jwks.json: "
                     f"{'served' if gate_on else 'not served'}, key: {source}")
        lines.append(f"- Forward auth: {'on' if getattr(cfg, 'forward_auth_enabled', False) else 'off'}, OAuth: "
                     f"{'on' if getattr(cfg, 'oauth_enabled', False) else 'off'}")
    if db is not None:
        db.close()
    return lines


def _read_log(path: str, n: int) -> list[str]:
    """The last `n` warnings and errors of a security log (format of `attach_security_log`)."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 512 * 1024))
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    found = [line for line in data.splitlines() if _LOG_LINE.match(line)]
    return found[-n:] if n > 0 else []


def build_report(cfg: Any, *, mode: str, source: str, db_path: str = "", log_path: str = "", lines: int = 20,
                 load_error: str = "") -> dict[str, str]:
    """The report as sections (ids of `SECTIONS`), already redacted."""
    red = _redactor(cfg)
    if db_path:
        red.register(db_path)
        red.register(os.path.abspath(db_path))
    if log_path:
        red.register(log_path)
        red.register(os.path.abspath(log_path))
    raw_log = _read_log(log_path, lines) if log_path else []
    log: list[str] = []
    for line in raw_log:
        m = _LOG_LINE.match(line)
        if m:
            log.append(f"{m.group(1)} {m.group(2)} {red.log_line(m.group(3))[:300]}")
    if not log_path:
        log_section = "- No security log given (--log PATH)"
    elif not log:
        log_section = "- No warnings or errors found in the security log"
    else:
        log_section = f"- Last {len(log)} warning(s) and error(s), redacted:\n\n```\n" + "\n".join(log) + "\n```"
    return {
        "environment": "\n".join(_environment(mode)),
        "configuration": "\n".join(_configuration(cfg, source, red, load_error)),
        "checks": "\n".join(_checks(cfg, mode, db_path, red, raw_log)),
        "log": log_section,
    }


TITLES = {"environment": "Environment", "configuration": "Configuration (shape only)", "checks": "Checks",
          "log": "Security log"}


def render(report: dict[str, str]) -> str:
    out = ["## TinySesam diagnostics report", "",
           ("Nothing has been sent. Read this report before you share it: host names, addresses, URLs, user names, "
            "paths and secrets are replaced by placeholders, but you know your setup best."), ""]
    for key in SECTIONS:
        out += [f"### {TITLES[key]}", "", report[key], ""]
    return "\n".join(out)


def issue_link(report: dict[str, str], mode: str = "library") -> tuple[str, list[str]]:
    """A prefilled link to the bug form, and the sections that did not fit (they say so in the link)."""
    from . import current_version
    fields = dict(report)
    left_out: list[str] = []

    def build() -> str:
        params = {"template": "bug.yml", "version": current_version(), "mode": mode}
        params.update(fields)
        return ISSUE_URL + "?" + urlencode(params, quote_via=quote)

    url = build()
    for key in ("log", "configuration", "checks", "environment"):
        if len(url) <= LINK_MAX:
            break
        fields[key] = TOO_LONG
        left_out.append(key)
        url = build()
    return url, left_out


# --- command ----------------------------------------------------------------------------------------------------------

def _load_config(spec: str) -> Any:
    """`module:attr` or `path/to/file.py:attr` → a TinySesamConfig (also from a TinySesam or a factory)."""
    from .config import TinySesamConfig
    target, _, attr = spec.rpartition(":")
    if not target:
        target, attr = spec, "config"
    if target.endswith(".py") or os.sep in target:
        loader = importlib.util.spec_from_file_location("_tinysesam_diagnose_config", target)
        if loader is None or loader.loader is None:
            raise ImportError("cannot load the file")
        module = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(module)
    else:
        if os.getcwd() not in sys.path:
            sys.path.insert(0, os.getcwd())
        module = importlib.import_module(target)
    obj = getattr(module, attr)
    if callable(obj) and not isinstance(obj, TinySesamConfig) and not hasattr(obj, "cfg"):
        obj = obj()
    if hasattr(obj, "cfg") and isinstance(obj.cfg, TinySesamConfig):
        obj = obj.cfg
    if not isinstance(obj, TinySesamConfig):
        raise TypeError(f"{spec} is a {type(obj).__name__}: expected a TinySesamConfig, a TinySesam (its `cfg` is "
                        "taken) or a function returning one")
    return obj


def run(argv: list[str], *, mode: str, prog: str, config_loader: Optional[Callable[[], Any]] = None) -> int:
    """`diagnose` for both entry points: the library loads `--config`, the gateway reads its environment."""
    ap = argparse.ArgumentParser(
        prog=prog,
        description="Print a diagnostics report and a prefilled link to the bug form. Makes no network request, "
                    "writes nothing; check the report before you send it.")
    if config_loader is None:
        ap.add_argument("--config", default="",
                        help="your configuration as module:attr or file.py:attr — a TinySesamConfig, a TinySesam, "
                             "or a function returning one (imports your module)")
    ap.add_argument("--db", default="", help="the database (default: db_path of the configuration); opened read-only")
    ap.add_argument("--log", default="", help="the security log (default: security_log of the configuration)")
    ap.add_argument("--lines", type=int, default=20, help="how many warnings and errors of the log (default 20)")
    ap.add_argument("--no-link", action="store_true", help="print the report only, without the link")
    a = ap.parse_args(argv)

    cfg = None
    load_error = ""
    if config_loader is not None:
        source = "environment of the gateway"
        try:
            cfg = config_loader()
        except (Exception, SystemExit) as e:      # a missing variable ends config_from_env with SystemExit
            load_error = type(e).__name__ + (f": {e}" if str(e) else "")
    elif a.config:
        source = "a Python object (--config)"
        try:
            cfg = _load_config(a.config)
        except Exception as e:
            load_error = type(e).__name__
    else:
        source = "none (--config not given)"
    db_path = a.db or (getattr(cfg, "db_path", "") if cfg is not None else "")
    log_path = a.log or (getattr(cfg, "security_log", "") if cfg is not None else "")
    report = build_report(cfg, mode=mode, source=source, db_path=db_path, log_path=log_path,
                          lines=max(0, min(a.lines, 200)), load_error=load_error)
    print(render(report))
    if not a.no_link:
        url, left_out = issue_link(report, mode)
        print("### Report a bug")
        print()
        print("Check the report above, then open this link — it fills in the bug form, you submit it yourself:")
        print()
        print(url)
        if left_out:
            print()
            print("The link was too long; paste these sections from the report into the form: " + ", ".join(left_out))
        print()
        print("A security vulnerability does not belong in a public issue — see SECURITY.md for the private way.")
    return 0
