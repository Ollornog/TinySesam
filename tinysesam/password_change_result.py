"""The result of a password change: `change_password` (0.22.0).

PO decision 2026-09-27: after the login building block (`login_*` → `LoginResult`) the
password change also gets a building block for custom pages. Until then there was only the route
`POST /auth/password`; whoever built a custom account page assembled it from `set_password` and the
inner checkers — without the own lockout for the old password (R4-10), without ending
the other sessions and without the log lines.

A type of its own and not `LoginResult`: a password change signs nobody in and rotates no
session token — `next_url`, `next_factor`, `done`, `set_cookie()` and `redirect()` would have
no meaning here. Instead it carries what only it has to say: how many of the account's API keys
survive the change (`api_keys_active`). The shape is the same as for `LoginResult` — `ok`,
`reason`, `status`, `message`, `bool(result)`, frozen, fail-closed: on a failure
nothing has changed.

Expected outcomes — old password wrong, lockout, throttle, new password too weak — are
**results, not exceptions**; `status` and `message` are what `POST /auth/password`
answers (the route calls exactly this building block).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class PasswordChangeResult:
    """What a password change resulted in: success or the reason against it, with HTTP status and text.

    `if not result:` asks for success (`ok`). On success the new password applies, the account's
    other sessions are ended (the own one continues, its cookie stays valid), and
    `api_keys_active` says how many API keys remain valid. On a failure nothing has
    changed; `status`/`message` are what `POST /auth/password` would answer.
    """

    #: Is the new password set? Exactly when `reason == "ok"`; `bool(result)` is the same value.
    ok: bool
    #: Why (not): one of the values in `REASONS`. For programs — the text is in `message`.
    reason: str
    #: The HTTP status of `POST /auth/password`: 200 on success, otherwise 400, 401, 403 or 429.
    status: int
    #: The translated text for the user (language from `config.lang`); empty on success.
    message: str = ""
    #: How many of the account's API keys remain valid — they survive the change on purpose (they
    #: belong to automations), it is not concealed. Only on success, otherwise 0.
    api_keys_active: int = 0

    #: Every value `reason` can take: `ok`; `missing` (old password empty, 400, does not count
    #: as a failed attempt); `invalid` (old password wrong, 403); `locked` (lockout after
    #: `password_change_max_attempts` failed attempts, 429); `ratelimit` (throttle per IP, 429);
    #: `policy` (the new password violates the password policy, 400 — the reason is in `message`);
    #: `no_session` (no full session, 401; 403 if the request shows an
    #: API key instead of a session).
    REASONS: ClassVar[tuple] = ("ok", "missing", "invalid", "locked", "ratelimit", "policy", "no_session")

    def __post_init__(self) -> None:
        if self.reason not in self.REASONS:
            raise ValueError(f"unknown reason {self.reason!r} (allowed: {', '.join(self.REASONS)})")
        if bool(self.ok) != (self.reason == "ok"):
            raise ValueError("ok and reason contradict each other")

    def __bool__(self) -> bool:
        return bool(self.ok)
