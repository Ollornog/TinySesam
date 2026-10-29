"""The result of a sign-in step: `login_password`, `login_pin`, `login_totp` — and of a step-up confirmation: `confirm_password`, `confirm_pin`, `confirm_totp` (0.22.0).

PO finding 2026-09-26: the README showed `check_password` + `start_session` as the way to a
custom login page. The inner checkers do not throttle, though — lockout, failed-attempt counter,
series, IP throttle and the lines for fail2ban existed only in the built-in routes. Anyone
following the pattern let passwords (or a four-digit PIN) be guessed as fast as the server answers.

The public way since then is the three `login_*` methods. They do exactly what the built-in
routes do, because those call them (one source, no drift). What comes back is a
`LoginResult`: success or the reason against it, with the HTTP status and the text the built-in
page shows.

Since the PO decision of 2026-09-27 the step-up building blocks `confirm_*` (the confirmation
before sensitive actions, called by `POST /auth/reauth`) also return a `LoginResult`: a
confirmation is a renewed sign-in on the running session, and the fields fit without remainder —
on success `done=True` and no open factor, `redirect()`/`set_cookie()` set the renewed
token (F-06). A separate type would have repeated every field and both methods, and a custom
page would have had to learn two shapes for the same pattern.

The names are English (PO decision 2026-09-27), like the rest of the tier-A surface. The values
of `reason` are short English codes for programs; the audit and log lines (fail2ban!)
keep their own words — a `reason` is not a log line.

Expected outcomes — wrong password, lockout, throttle, directory gone — are **results,
not exceptions**: the built-in route has to render them as a page with a status, a custom one as
a form or JSON. Fail-closed by construction: on every failure there is no session and
no cookie. Whoever ignores the result lands on the target page without a session and is sent
from there back to the sign-in.

The session token is deliberately **not a field**: the mistake the old README modelled (the
tuple from `start_session` in the cookie) came precisely from handling the token. `set_cookie()`
and `redirect()` set it correctly — including a new CSRF token on a fresh sign-in.
It hangs on the object, but outside the dataclass fields: `repr()`, `==` and
`dataclasses.asdict()` do not see it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Optional


@dataclass(frozen=True)
class LoginResult:
    """What a sign-in step or step-up confirmation resulted in: success or the reason against it, with HTTP status and text.

    `if not result:` asks for success (`ok`). On success `result.redirect()` sets the
    session cookie and leads to the next factor or to the target; on failure there is
    no session, and `status`/`message` are what the built-in page would show.
    """

    #: Did the step sign in (or freshly confirm)? Exactly when `reason == "ok"`;
    #: `bool(result)` is the same value.
    ok: bool
    #: Why (not): one of the values in `REASONS`. For programs — the text is in `message`.
    reason: str
    #: The HTTP status of the built-in page: 303 on success, otherwise 400, 401, 403, 404, 429 or 503.
    status: int
    #: The translated text for the user (language from `config.lang`); empty on success.
    message: str = ""
    #: The checked target (`safe_next`, with mount prefix): on success the next factor step
    #: or `next`, otherwise `next` for the form — for `no_session` the login page.
    next_url: str = ""
    #: The open factor after this step (e.g. `"totp"`), for a custom page of the next
    #: step. On a failure in the follow-up step the same factor once more, otherwise None.
    next_factor: Optional[str] = None
    #: Is the session fully signed in? True only on success and with no open factor.
    done: bool = False
    #: The signed-in account (like `get_user`) — only on success, otherwise None.
    user: Optional[dict] = None

    #: Every value `reason` can take: `ok`; `missing` (required field empty, 400); `invalid`
    #: (password, PIN or code wrong, 401); `locked` (lockout after failed attempts, 429);
    #: `locked_series` (too many failed attempts in a row, does not expire, 429); `ratelimit` (throttle
    #: per IP, 429); `directory_down` (LDAP directory unreachable, 503); `method_disabled`
    #: (method disabled or no first factor here, 404; for `confirm_*` 403: this account
    #: cannot confirm here with this method, `stepup_options`); `no_session` (without a
    #: session, 401 — for `login_totp` and `confirm_*`; for `confirm_*` 403 if the request
    #: shows an API key instead of a session). `locked` also covers the deferral behind a
    #: pending directory sign-in (G9) — otherwise the reason would reveal that someone
    #: else is currently signing in under the identifier.
    REASONS: ClassVar[tuple] = ("ok", "missing", "invalid", "locked", "locked_series", "ratelimit",
                                "directory_down", "method_disabled", "no_session")

    def __post_init__(self) -> None:
        if self.reason not in self.REASONS:
            raise ValueError(f"unknown reason {self.reason!r} (allowed: {', '.join(self.REASONS)})")
        if bool(self.ok) != (self.reason == "ok"):
            raise ValueError("ok and reason contradict each other")
        # Without a session: only `_with_session` attaches token and TinySesam — outside the fields.
        object.__setattr__(self, "_token", None)
        object.__setattr__(self, "_auth", None)

    @classmethod
    def _with_session(cls, auth: Any, token: Optional[str], **fields) -> "LoginResult":
        """A success whose session token still has to go into the cookie (None: the cookie is already valid)."""
        result = cls(**fields)
        object.__setattr__(result, "_auth", auth)
        object.__setattr__(result, "_token", token)
        return result

    def __bool__(self) -> bool:
        return bool(self.ok)

    def set_cookie(self, response) -> None:
        """Set the session cookie in `response` if the step produced a new token.

        Via `TinySesam.set_cookie`: the kind of cookie follows the session ("Stay signed in"),
        and a sign-in that has just come about gets a new CSRF token in the process. Without a new token
        (a chain step on a running session, every failure) it does nothing. For a
        custom response — JSON instead of a redirect —, otherwise `redirect()`."""
        if self._token and self._auth is not None:     # type: ignore[attr-defined]
            self._auth.set_cookie(response, self._token)   # type: ignore[attr-defined]

    def redirect(self):
        """A redirect (303) to `next_url`, with the session cookie set if there is one.

        On success the usual ending of a custom route: to the open factor or to the target.
        For `no_session` it leads to the login page; on any other failure to `next`,
        without a session — from there the guard sends back to the sign-in."""
        from fastapi.responses import RedirectResponse
        response = RedirectResponse(self.next_url, 303)
        self.set_cookie(response)
        return response
