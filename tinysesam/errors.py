"""Error types an embedding app can react to.

Up to 0.18.0 TinySesam raised only built-in types: `ValueError` from the constructor guards,
`RuntimeError` from a missing extra, `MailNotConfigured` (not exported). Anyone who wanted to
tell at startup whether the **configuration** is wrong or a **package** is missing had to read
the message text — the most brittle way to control a program, and broken at the next
change of translation.

Each type here additionally inherits from the built-in one it replaces. Existing code that
writes `except ValueError` keeps catching — nothing breaks, it just becomes distinguishable:

    from tinysesam import ConfigError, MissingExtra, TinySesamError

    try:
        auth = TinySesam(config)
    except MissingExtra as e:
        print("Please install:", e)             # pip install 'tinysesam[passkey]'
    except ConfigError as e:
        print("Check configuration:", e)        # contradictory switches
"""
from __future__ import annotations

from typing import Optional


class TinySesamError(Exception):
    """Base of all own errors — `except TinySesamError` catches everything from here."""


class ConfigError(TinySesamError, ValueError):
    """The configuration contradicts itself or promises something that does not take effect.

    Inherits from `ValueError` because the guards raised that so far.

    Two fields are set where an **identifier** is involved (`create_user`): `field` is
    `"username"` or `"email"`, `owner_id` the ID of the account that owns the identifier.
    This way nobody has to read the message text to tell the two cases apart — the text is
    translated and belongs to the human, the attributes to the program. Otherwise empty or `None`."""

    #: "username" | "email" | "" — the affected field, where there is one.
    field: str = ""
    #: ID of the account that already owns the identifier (otherwise None).
    owner_id: "Optional[int]" = None


class MissingExtra(TinySesamError, RuntimeError):
    """An enabled switch needs an extra that is not installed.

    Carries the name of the extra so an app can build the install line instead of fishing it
    out of the message text."""

    def __init__(self, message: str, extra: str = ""):
        super().__init__(message)
        self.extra = extra


class MailNotConfigured(TinySesamError, RuntimeError):
    """A mail was supposed to go out, but no mailer is set up."""


class StateError(TinySesamError, RuntimeError):
    """The operation does not fit the state of the account — and is therefore refused.

    Neither a configuration nor an installation error: the request is fine in itself, but it
    would overwrite something that already applies. First case: starting a TOTP setup although
    a confirmed second factor already exists (finding B2-1) — there the silent success was
    the problem, not the abort."""


class RoleError(TinySesamError, ValueError):
    """A catalog action that does not go through. `code` says why — the text is for people, `code` for programs:

    * `invalid` — the name: a comma, a control or format character, surrounding spaces, empty, longer than 64, or a
      role level entry that would be ambiguous;
    * `exists` — the name (or its casefold) is in the catalog already;
    * `in_config` — the configuration names the role (or `admin`/`__admin__`);
    * `in_use` — the role is held or waiting somewhere (`usage` says where);
    * `in_ladder` — the role is one level of a role level entry whose other roles are still known: delete the whole
      entry;
    * `not_found` — no such catalog role (or role level entry);
    * `full` — the catalog holds `LIMIT` roles;
    * `forbidden` — the actor may not change the catalog (administrators only)."""

    def __init__(self, code: str, message: str, usage: Optional[dict] = None, role: str = ""):
        super().__init__(message)
        #: Why: see the list above.
        self.code = code
        #: `in_use`: `{role: {"users", "keys", "services", "links", "approvals"}}` (as `TinySesam.role_usage`).
        self.usage = usage or {}
        #: The role (or role level entry) concerned.
        self.role = role
