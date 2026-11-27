"""The server's configuration file (T-97, ADR-16): `TINYSESAM_CONFIG=/etc/tinysesam.toml`.

The file fills the whole `TinySesamConfig` — the same core as the library, not the OIDC-only preset of the gateway's
environment variables. Its keys are the field names of `TinySesamConfig` (see CONFIGURATION.md), tables for the fields
that hold a mapping (`apps`, `oidc_clients`, `forward_apps`, …). Read with the standard library (`tomllib`); a key that
is no field is a start error with the nearest field named — a typo silently ignored would leave a feature off that the
operator believes on.

Secrets never stand in the file as a literal: a secret field (`SECRET_FIELDS`, and `client_secret` inside an
`oidc_clients` entry) takes `"env:NAME"` (the value of the environment variable NAME) or the sibling key
`<field>_file = "/run/secrets/…"` (the file's content, a trailing line break removed). A literal there ends the start:
the file is meant to be reviewed and kept in git, and a secret in it would travel with every copy. This is checked
here, where the source of a value is still visible; `config_check` sees only the resolved value.

The gateway's environment variables overlay the file (container habit): a variable that is SET wins over the key it
stands for (`ENVIRONMENT_FIELDS`, the same names as `python -m tinysesam.gateway --help`); one that is not set changes
nothing. Without `TINYSESAM_CONFIG` the gateway is configured by its environment variables exactly as before.
"""
from __future__ import annotations

import dataclasses
import difflib
import os

from .config import TinySesamConfig

#: The variable naming the file.
CONFIG_VARIABLE = "TINYSESAM_CONFIG"

#: Fields that hold a secret: only `env:NAME` or `<field>_file` in the file, never a literal.
SECRET_FIELDS = ("oidc_client_secret", "smtp_password", "ldap_bind_password")

#: Keys inside an `oidc_clients` entry that hold a secret (same rule).
CLIENT_SECRET_KEYS = ("client_secret",)

#: The prefix of a value that names an environment variable.
ENV_PREFIX = "env:"


class FileError(ValueError):
    """The configuration file cannot be used; the message names the key and what to do."""


def field_names() -> tuple:
    """The keys a file may set: every field of `TinySesamConfig`."""
    return tuple(f.name for f in dataclasses.fields(TinySesamConfig))


def _secret(where: str, value, sibling_file, env) -> str:
    """Resolve one secret: `env:NAME`, the content of the sibling `_file`, or empty. A literal is refused."""
    if sibling_file is not None:
        if value not in (None, ""):
            raise FileError(f"{where}: set either {where} or {where}_file, not both")
        if not isinstance(sibling_file, str) or not sibling_file:
            raise FileError(f"{where}_file: a path to a file holding the secret")
        try:
            with open(sibling_file, encoding="utf-8") as fh:
                return fh.read().rstrip("\r\n")
        except OSError as e:
            raise FileError(f"{where}_file={sibling_file!r} cannot be read: {e.strerror or e}") from None
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise FileError(f"{where}: a secret is text — \"env:NAME\" or {where}_file")
    if not value.startswith(ENV_PREFIX):
        raise FileError(f"{where}: a secret never stands in the file as a literal — write \"env:NAME\" (the value of "
                        f"the environment variable NAME) or {where}_file = \"/run/secrets/…\"")
    name = value[len(ENV_PREFIX):].strip()
    if not name:
        raise FileError(f"{where}: \"env:\" needs the name of an environment variable")
    resolved = env.get(name)
    if resolved is None:
        raise FileError(f"{where}: the environment variable {name} (named by \"env:{name}\") is not set")
    return resolved


def _clients(raw, env) -> dict:
    """`oidc_clients`: host → entry, each `client_secret` through the secret rule."""
    if not isinstance(raw, dict):
        raise FileError("oidc_clients: a table of hosts, e.g. [oidc_clients.\"app.example.com\"]")
    out = {}
    for host, entry in raw.items():
        if not isinstance(entry, dict):
            raise FileError(f"oidc_clients.{host!r}: a table (client_id, client_secret, …)")
        entry = dict(entry)
        for key in CLIENT_SECRET_KEYS:
            where = f"oidc_clients.{host!r}.{key}"
            secret = _secret(where, entry.pop(key, None), entry.pop(f"{key}_file", None), env)
            if secret:
                entry[key] = secret
        out[str(host).strip().lower()] = entry
    return out


def values_from_file(path: str, env=None) -> dict:
    """The field values a file sets — secrets resolved, nothing defaulted. Raises `FileError`."""
    import tomllib
    env = os.environ if env is None else env
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except OSError as e:
        raise FileError(f"{CONFIG_VARIABLE}={path!r} cannot be read: {e.strerror or e}") from None
    except tomllib.TOMLDecodeError as e:
        raise FileError(f"{path}: not valid TOML — {e}") from None
    known = set(field_names())
    secret_files = {f"{name}_file" for name in SECRET_FIELDS}
    unknown = sorted(k for k in raw if k not in known and k not in secret_files)
    if unknown:
        hints = []
        for key in unknown:
            near = difflib.get_close_matches(key, sorted(known | secret_files), n=1)
            hints.append(f"{key!r}" + (f" (did you mean {near[0]!r}?)" if near else ""))
        raise FileError(f"{path}: not a field of TinySesamConfig: {', '.join(hints)} — the keys are the field names "
                        "in CONFIGURATION.md")
    values = {k: v for k, v in raw.items() if k in known and k not in SECRET_FIELDS}
    for name in SECRET_FIELDS:
        if name in raw or f"{name}_file" in raw:
            values[name] = _secret(name, raw.get(name), raw.get(f"{name}_file"), env)
    if "oidc_clients" in values:
        values["oidc_clients"] = _clients(values["oidc_clients"], env)
    return values


def config_from_file(path: str, overlay: dict, env=None) -> TinySesamConfig:
    """The full configuration: the library's defaults, the file, then the environment's overlay (`overlay`, only
    the variables that are set). Raises `FileError` for the file and `ConfigError` for a contradiction."""
    values = values_from_file(path, env)
    values.update(overlay)
    return TinySesamConfig(**values)
