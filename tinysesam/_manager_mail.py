"""The building block `mail` of `TinySesam`: mail: notices of security events and sending.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import time
from . import security
from .store import norm_email
from fastapi import Request
from typing import Optional
from . import manager as _manager
from .manager import (
    _proof_on_account,
)


def _security_event(self, event: str, user_id, **details) -> None:
    """Call `on_security_event` for an event from `SECURITY_EVENTS`, if set.

    An error in the hook does **not** abort the operation — the change has by then
    already been written, and a failed mail server must not make the password change
    fail. It does land in the security log, though: a notification that silently
    fails to appear is worse than none that nobody relies on. The hook runs
    synchronously in the request; whoever sends mail does better to put it in a queue."""
    self._access_notice(event, user_id, details)
    hook = self.on_security_event
    if hook is None:
        return
    line = self.store.get_user(user_id)
    if line is None:
        return
    account = {"id": line["id"], "username": line["username"], "email": line["email"],
             "display_name": line["display_name"]}
    try:
        hook(event, account, dict(details))
    except Exception as e:
        security.seclog.warning("on_security_event failed event=%s user_id=%s: %s",
                                event, line["id"], security.for_log(repr(e)))


def _access_notice(self, event: str, user_id, details: dict) -> None:
    """Tell the owner by mail about new access to the account (T-47, `notify_new_access`).

    Only for `_ACCESS_MAIL_EVENTS`, only with delivery configured, only to a verified address of an
    interactive account — and at most one mail per account and event a minute (a flood of
    API keys must not become a flood of mails). Sending happens in the background outbox of
    the lockout notices: the request does not wait for the mail server, and a failure there does
    not undo the change. The text names what happened, when and from which address — never a
    secret, never a link (a mail that asks to click is what phishing looks like)."""
    if event in self._FAILURE_MAIL_EVENTS:
        # T-63: a sign-in after failed attempts belongs to the failed attempts, not to new access — the same
        # switch as the lockout notice.
        if not self.cfg.notify_login_failures:
            return
    elif event not in self._ACCESS_MAIL_EVENTS or not self.cfg.notify_new_access:
        return
    if event == "password_changed" and not details.get("by_operator"):
        return
    if not self.mail_configured():
        return
    if not self.rl.allow(f"access_notice:{user_id}:{event}", 1, 60):
        return
    ip = self._request_ip()
    when = _manager._now()

    def _send():
        u = self.store.get_user(user_id)
        if not u or u["is_service"] or not u["email"] or not _proof_on_account(u):
            return
        what = self.t("notice." + event, failures=details.get("failures", ""))
        text = self.t("mail.access.text", name=u["username"], what=what,
                      time=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(when)),
                      ip=security.for_log(ip) or self.t("mail.unknown"))
        self.send_mail(u["email"], self.t("mail.access.subject", what=what), text)
        self.store.audit_log("access_notice", u["username"], ip, f"event={event}")

    self._notice_outcome.enqueue(_send)


def ensure_admin(self, username, password) -> bool:
    """Bootstrap: creates an admin IF no user exists yet. True on creation."""
    if self.store.user_count() == 0:
        uid = self.create_user(username, password, is_admin=True)
        self._first_owner(uid)
        return True
    return False


# ---------- Email sending ----------
def set_mailer(self, fn):
    """Attach a custom mail sender: fn(to, subject, text, html=None). Overrides SMTP."""
    self._mailer_override = fn


def mail_configured(self) -> bool:
    """Can a mail go out at all — via SMTP or via `set_mailer`?"""
    return bool(self._mailer_override or self.cfg.smtp_host)


def send_mail(self, to, subject, text, html=None):
    """Send a mail — via SMTP or the route set with `set_mailer`."""
    from .mailer import SMTPMailer
    fn = self._mailer_override or SMTPMailer(self.cfg)
    fn(to, subject, text, html)


def _mail_destination_ok(self, address, purpose, bucket="mail") -> bool:
    """May another mail go to this address? Throttled per **target**, not per sender (R4-04).

    The routes' IP throttle protects the server, not the mailbox: whoever triggers "forgot password"
    for a foreign account via changing addresses would fill its mailbox
    without limit. The rejection is invisible to the outside (same response as otherwise) and
    appears in the audit log so that the operator sees the flood.

    `topf` separates quotas: sign-in link and reset share one (both bring the
    owner into the account — whoever triggers them for them sends them usable links). The notice
    of the registration has one of its own (attack A2): any stranger triggers it, it carries
    no token, and in the shared bucket three foreign registrations used up the
    quota with which the owner sends themselves a link — with operation using only the
    sign-in link, a repeatable lockout.
    """
    key_name = f"{bucket}:" + (norm_email(address) or "")
    if self.rl.allow(key_name, self._sec("mail_per_address_max"),
                     self._sec("mail_per_address_window_sec")):
        return True
    self.audit("mail_ratelimit", detail=f"{purpose} to={address}")
    return False


def _token_hash(self, raw) -> str:
    """The stored digest of a one-time token: an HMAC with the pepper keyring (T-72), never a plain sha256."""
    return self.store.token_digest(str(raw), "magic")


def _token_mail(self, raw, to, subject, text, html=None) -> bool:
    """Send a mail with a one-time token. If delivery fails, the token is consumed
    immediately (B6-12): otherwise a valid, never delivered link lay in the database until expiry
    — a piece of evidence without a recipient, and with a relay that does deliver the mail after all,
    a link which the sender believes does not exist.

    If the token has already been discarded or redeemed before sending, no mail goes out:
    if the outbox lies between creation and sending, the operator may have locked the account in the
    meantime (H-18) — the mail would then carry only a dead link.

    True if the mail went out; False if the token was already gone (G12a counts only
    delivered links); a delivery error comes as an exception."""
    line = self.store.get_magic_token(self._token_hash(raw))
    if not line or line["used_at"]:
        return False
    try:
        self.send_mail(to, subject, text, html)
    except Exception:
        self.store.expire_magic_token(self._token_hash(raw))
        raise
    return True


def after_response(self, resp, task, on_overflow=None):
    """Run `task()` only AFTER the response has been sent, in the own mail worker
    (`mailer.Outbox`, R4-05/B6-6). Returns `resp`."""
    from starlette.background import BackgroundTask
    resp.background = BackgroundTask(self._outbox.afterwards(task, on_overflow))
    return resp


def _token_rejected(self, purpose, request: Optional[Request] = None, reason="invalid"):
    """An invalid/expired/consumed one-time token was presented (B5-18).

    Until now that left no trace: whoever tried out reset or sign-in tokens was seen by the
    operator nowhere. Audit line for the operator, security log with the word of the
    non-login checks (`failed verification`) — a stale link in one's own
    mailbox is not a sign-in attempt and must not lock anyone out via fail2ban.
    """
    ip = self.client_ip(request) if request is not None else None
    # The security log gets every line: it rotates, and fail2ban's verify jail
    # bans from it exactly the one who tries out links.
    self._rejected(None, ip, f"token_{purpose}", login=False)
    # The audit log, by contrast, is never cleaned up by `gc()`, and the routes are anonymous and unthrottled
    # (attack A3): every GET on /auth/magic/<nonsense> wrote a database row permanently —
    # a disk could be filled that way. The cap is therefore global per time window,
    # not per IP (an attacker changes that), and when the cap applies, exactly
    # ONE line about it appears in the audit — otherwise the operator would not see the flood.
    window = self._TOKEN_AUDIT_WINDOW_SEC
    if self.rl.allow("audit:token_invalid", self._TOKEN_AUDIT_MAX, window):
        self.audit("token_invalid", ip=ip, detail=f"purpose={purpose} reason={reason}")
    elif self.rl.allow("audit:token_invalid_throttled", 1, window):
        self.audit("token_invalid_throttled", ip=ip,
                   detail=f"more than {self._TOKEN_AUDIT_MAX} in {window}s — further ones only in the security log")
