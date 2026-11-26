"""The building block `links` of `TinySesam`: sign-in links: one-time tokens and links without mail.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import secrets
from . import config_check
from . import security
from . import totp as _totp
from .errors import ConfigError
from .store import read_payload
from typing import Optional
from . import manager as _manager
from .manager import (
    _REQUEST,
)


# ---------- Magic / one-time tokens ----------
def create_magic_token(self, purpose, user_id=None, email=None, ttl_min=None, payload=None) -> str:
    """Create a one-time token (plaintext return). Only its keyed digest is in the DB (`_token_hash`, T-72)."""
    raw = secrets.token_urlsafe(32)
    h = self._token_hash(raw)
    ttl = int(ttl_min if ttl_min is not None else self.cfg.magiclink_ttl_min) * 60
    self.store.add_magic_token(h, purpose, _manager._now() + ttl, user_id, email, payload)
    return raw


def magic_url(self, raw, base_url, purpose="login") -> str:
    """The link the recipient clicks — path depending on purpose (`TOKEN_PATHS`). `base_url`
    is checked: a foreign host raises `ConfigError` — in a route
    `public_base(request)` supplies the checked base.

    The check sits here because all four mail routes converge here: reset,
    sign-in link, confirmation and invitation. So the protection applies regardless of who builds the
    route — also for an app with its own form. Permitted are `base_url`, a host
    from `trusted_redirect_hosts` and loopback.
    """
    from urllib.parse import quote
    path = self.TOKEN_PATHS[purpose].format(t=quote(str(raw), safe=""))
    return f"{self._checked_base(base_url)}{path}"


def redeem_magic(self, raw, purpose=None) -> Optional[dict]:
    """Redeem a token (one-shot). Returns {purpose,user_id,email,payload} or None (invalid/expired/used).

    `payload`: an address-change link carries `old`, the previous address."""
    if not raw:
        return None
    h = self._token_hash(raw)
    row = self.store.get_magic_token(h)
    if not row or (purpose and row["purpose"] != purpose):
        return None
    if not self.store.use_magic_token(h):
        return None
    return {"purpose": row["purpose"], "user_id": row["user_id"], "email": row["email"],
            "payload": read_payload(row["payload"])}


def _app_link_refused(self, data: Optional[dict]) -> bool:
    """Is this sign-in link one an application obtained (account API: creation, a new link, an access reset) for
    an account that is no longer wholly that application's? Then it signs nobody in.

    An application holds the link of every account it creates until the first sign-in. If the operator or a
    delegate then gives the account a role outside the allowlist (an `approver_role`, the part of another
    application), makes it administrator or a delegate, or releases it, the application would sign in as that
    account through the link it still holds. Checked at the door, not at each place that changes an account, so
    no path is missed — panel, delegate, approval, CLI, an embedding application, the identity provider. The same
    once anyone has signed in to the account after the link was issued: the application's link is for the way
    in, not for a second key beside the person's own."""
    if not data:
        return False
    payload = data.get("payload") or {}
    app_id = payload.get("app") if isinstance(payload, dict) else None
    if not app_id:
        return False
    u = self.store.get_user(data["user_id"]) if data.get("user_id") is not None else None
    app = self._provisioning().apps().get(str(app_id))
    if u is None or app is None:
        return True
    roles = self.user_roles(u)
    delegates = self._provisioning()._delegate_roles()
    if not config_check.app_visible(app["id"], u, roles, delegates) or not config_check.may_manage(
            frozenset(app["roles"]), None, u, roles, delegate_roles=delegates, without_roles=True):
        return True
    issued, last = payload.get("issued_at"), u["last_login_at"]
    return bool(last) and (not isinstance(issued, int) or int(last) > issued)


def peek_magic(self, raw, purpose=None) -> Optional[dict]:
    """Check a token WITHOUT consuming it (for the invite flow: redeem only at registration).
    Return as for `redeem_magic`."""
    if not raw:
        return None
    row = self.store.get_magic_token(self._token_hash(raw))
    if not row or row["used_at"] or row["expires_at"] < _manager._now():
        return None
    if purpose and row["purpose"] != purpose:
        return None
    return {"purpose": row["purpose"], "user_id": row["user_id"], "email": row["email"],
            "payload": read_payload(row["payload"])}


def create_invite(self, email, base_url, roles=None, is_admin=False, ttl_min=None) -> dict:
    """Create an invitation (+ optionally send it). Return {url, token}. The token carries the
    intended roles/admin rights; it is redeemed only at registration. `base_url`
    is checked (`ConfigError` for a foreign host, see `magic_url`).

    The check happens before the token is issued, so that a rejected call leaves no
    invitation token behind. If sending fails, the token is invalidated (B6-12).

    `ttl_min` defaults to `invite_ttl_min` (24 h) — an invitation waits in a mailbox for a person who did not ask
    for it, unlike the 10 minutes of a sign-in or reset link (`magiclink_ttl_min`). Allowed are 1 minute to
    `signin_link_max_ttl_min`, the bound of every hand-over link; anything else raises `ValueError`.
    """
    base_url = self._checked_base(base_url)
    self._refuse_role_names(roles)      # the invitee would carry them into the account (T-85)
    if ttl_min is None:
        ttl = int(self.cfg.invite_ttl_min)
    elif isinstance(ttl_min, bool) or not isinstance(ttl_min, int):
        raise ValueError(self.t("api.invalid", reason="ttl_min"))
    else:
        ttl = ttl_min
    if not 1 <= ttl <= int(self.cfg.signin_link_max_ttl_min):
        raise ValueError(self.t("api.signin_link_ttl", max=int(self.cfg.signin_link_max_ttl_min)))
    raw = self.create_magic_token("invite", email=email, ttl_min=ttl,
                                  payload={"roles": list(roles or []), "is_admin": bool(is_admin)})
    url = self.magic_url(raw, base_url, "invite")
    if email and self.mail_configured():
        # The mail names the lifetime: an invitation waits in a mailbox, and without it the person cannot tell
        # whether a link from yesterday still works (the reset mail names its minutes too).
        valid = self._duration(ttl)
        self._token_mail(raw, email, self.t("mail.invite.subject"),
                         self.t("mail.invite.text", url=url, valid=valid),
                         html=self.t("mail.invite.html", url=url, valid=valid))
    self.audit("invite_create", detail=email)
    return {"url": url, "token": raw}


def _duration(self, minutes: int) -> str:
    """A lifetime for a mail in the configured language: whole hours as hours, everything else as minutes."""
    minutes = int(minutes)
    if minutes >= 60 and minutes % 60 == 0:
        hours = minutes // 60
        return self.t("mail.hour") if hours == 1 else self.t("mail.hours", n=hours)
    return self.t("mail.minute") if minutes == 1 else self.t("mail.minutes", n=minutes)


def send_verify_email(self, user_id, email, base_url) -> bool:
    """Send the confirmation link for an address. False if there is no mailer.
    `base_url` is checked (`ConfigError` for a foreign host, see `magic_url`).
    If sending fails, the token is invalidated (B6-12) and the error is passed on.
    The link unlocks an account whose confirmation is pending (registration), never one
    that the operator has locked (admin panel, `set_disabled(user_id, True)`) — even if
    the link comes into being only after this lock, e.g. because the call waits via
    `after_response` (H-18).
    When redeemed it sets the evidence for the address (`email_verified`), as long as it is still the
    account's.
    """
    send = self._verify_mail(user_id, email, base_url)
    if send is None:
        return False
    send()
    return True


def _verify_mail(self, user_id, email, base_url):
    """Create the confirmation token NOW and return the sending as a function — or
    None if there is no mailer. `base_url` is checked as with `send_verify_email`.

    Separate, because registration only pushes the sending into the outbox (R4-05/B6-6),
    not the token issuing: the operator's lock discards open tokens (H-18).
    If the token only came into being in the mail worker, a lock in the waiting window found nothing, and
    the delayed link lifted it again afterwards (T-13 attack, mail × operation)."""
    base_url = self._checked_base(base_url)
    if not (email and self.mail_configured()):
        return None
    raw = self.create_magic_token("verify_email", user_id=user_id, email=email)
    url = self.magic_url(raw, base_url, "verify_email")

    def send():
        self._token_mail(raw, email, self.t("mail.verify.subject"),
                         self.t("mail.verify.text", url=url),
                         html=self.t("mail.verify.html", url=url))
    return send


def create_signin_link(self, user_id, ttl_min=None, next="/") -> dict:
    """Issue a one-time sign-in link for an account — without mail, to hand over by any channel.

    The same token as the mailed sign-in link (purpose `login`, redeemed at
    `/auth/magic/{token}` with the confirmation page of R4-02), so the same rules apply: single
    use, `magiclink_require_second_factor`, and it is discarded with the account's other open
    links when the account is disabled or its password is reset. Works without a mailer.

    The address comes **only** from `base_url` — never from a request's Host header (R4-01):
    whoever hands the link on would otherwise hand on an address the requester chose.

    `ttl_min` defaults to `magiclink_ttl_min`; allowed are 1 minute to `signin_link_max_ttl_min` (default 24 h,
    T-51 — NIST SP 800-63B-4 §4.2.2). Returns
    `{"url", "expires_at", "qr"}` — `qr` is a PNG data URI of the link, or None without the
    extra `[qr]`. The plaintext exists only in this return value; the database holds the hash.
    Audit `signin_link_issue` under the account, with `actor=` when an admin issues it.

    `next` is where the link leads once the sign-in (and a setup pass) is complete. It is stored with the token,
    not in the link, and must be a path or an http(s) address on the host of `base_url` or in
    `trusted_redirect_hosts` (`config_check.link_next_ok`, T-94).

    Raises `ConfigError` without `magiclink_enabled` (no route would redeem the link) or without
    `base_url`; `ValueError` for an unknown, disabled or service account, an invalid `ttl_min` or `next`, or
    — with `magiclink_first_login_only` — an account that is set up already (T-34).

    With a `login_chain`, an account that lacks factors for it is led through the setup pass
    (`/auth/setup`) after the link: it sets up what the chain demands before it is fully signed
    in (T-34)."""
    return self._signin_link(user_id, ttl_min=ttl_min, next=next)


def _signin_link(self, user_id, ttl_min=None, next="/", app_id: Optional[str] = None) -> dict:
    """`create_signin_link`, and for the account API (`app_id`): the token then names the application and the
    moment it was issued, so the door refuses it once the account is no longer wholly the application's
    (`_app_link_refused`) — however that came about."""
    if not self.cfg.magiclink_enabled:
        raise ConfigError("magiclink_enabled=False — a sign-in link would have no route that redeems it")
    if not str(self.cfg.base_url or "").strip():
        raise ConfigError("base_url is empty — a sign-in link is built only from base_url, "
                          "never from the Host header")
    base = self._checked_base(self.cfg.base_url)
    if ttl_min is None:
        ttl = int(self.cfg.magiclink_ttl_min)
    elif isinstance(ttl_min, bool) or not isinstance(ttl_min, int):
        raise ValueError(self.t("api.invalid", reason="ttl_min"))
    else:
        ttl = ttl_min
    if not 1 <= ttl <= int(self.cfg.signin_link_max_ttl_min):
        raise ValueError(self.t("api.signin_link_ttl", max=int(self.cfg.signin_link_max_ttl_min)))
    u = self.store.get_user(user_id) if user_id is not None else None
    if not u:
        raise ValueError(self.t("api.not_found"))
    # A link for a disabled account would never sign in (`apply_factor` refuses it) — say so
    # now instead of handing over a dead link. A service account has no interactive sign-in.
    if u["disabled"]:
        raise ValueError(self.t("api.account_disabled"))
    if u["is_service"]:
        raise ValueError(self.t("api.signin_link_service"))
    # `magiclink_first_login_only` (T-34): say it now instead of handing over a link that the
    # door refuses. Also for the admin — a forgotten factor is removed and a setup window opened
    # (`grant_mfa_enrollment`) first; then the link opens the setup pass.
    if not self._link_allowed(int(u["id"])):
        raise ValueError(self.t("api.signin_link_first_only"))
    # T-94: the target is checked HERE, where it is given — `safe_next` at the door would drop a wrong one in
    # silence and the person would land somewhere else than the issuer meant. It is stored with the token (the
    # payload), never in the link: nobody who holds the link can rewrite it. The door checks it once more.
    target = str(next or "/")
    if not config_check.link_next_ok(self.cfg, target):
        raise ValueError(self.t("api.invalid", reason="next"))
    payload: dict = {"next": target, "issued": "operator"}
    if app_id:
        payload.update(app=str(app_id), issued_at=_manager._now())
    raw = self.create_magic_token("login", user_id=int(u["id"]), ttl_min=ttl, payload=payload)
    url = self.magic_url(raw, base)
    # The audit names the target's host, not the address (a path or query may carry what is no log's business).
    where = security.host_name(target) if "://" in target else ""
    self.audit("signin_link_issue", str(u["username"]),
               detail=f"ttl_min={ttl}" + (f" next_host={security.for_log(where)}" if where else
                                          (" next=path" if target != "/" else "")))
    # T-47: a link is a way into the account for whoever holds it — the holder learns of it
    # (hook, mail with `notify_new_access`, "Recent activity"). `by_operator`: someone else issued it.
    a = _REQUEST.get() or {}
    by_operator = bool(a.get("actor")) and str(a.get("actor")).lower() != str(u["username"]).lower()
    self._security_event("signin_link_issued", int(u["id"]), ttl_min=ttl, by_operator=by_operator)
    return {"url": url, "expires_at": _manager._now() + ttl * 60, "qr": _totp.qr_data_uri(url)}
