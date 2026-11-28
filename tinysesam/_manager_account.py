"""The building block `account` of `TinySesam`: self-service: username and address, the own account as data, the app frame (T-91).

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import html as _html
import json
import re
import sqlite3
from . import security
from . import topbar as _topbar
from .errors import ConfigError
from .errors import StateError
from .store import name_invalid
from .store import norm_email
from .store import norm_identifier
from .store import valid_email
from fastapi import Request
from typing import Optional
from .manager import (
    _DictHeaderLines,
    _host_from,
)


def change_username(self, user_id, new_username, ip: Optional[str] = None, *,
                    by_operator: bool = False) -> str:
    """Change one's own username. Returns the new name, `ValueError` with the
    reason if it is not possible.

    **A self-chosen name does not bind via LDAP/SAML** (G2-N): the account afterwards carries
    `users.name_self_chosen`, and a sign-in via a federated source never binds it
    via the name — otherwise a local account renames itself after someone from the directory
    and inherits identifier and groups at their next sign-in. Whoever renames as **operator**
    (from the embedding service, e.g. to resolve a collision) passes
    `by_operator=True`: then the name stands for the operator, the marker is dropped, and the
    audit line says `by=operator`.

    Everything attached to the account — sessions, keys, factors, roles, bindings to LDAP/SAML/OIDC —
    hangs on the ID, not on the name, and stays. Outwardly `Remote-User` changes; `Remote-Id`
    is stable. The same rules as on creation (free in BOTH namespaces, no
    control characters) and three of its own:

    * **No name with `@`**, except the own taken address: otherwise someone would occupy the
      address of a person who does not yet exist here, and that person would get
      "taken" at registration (the same rule as registration with confirmation, attack A1).
    * **No name from `admin_identifiers`**: whoever calls themselves that would become
      first admin at the next login. The response is the same as for "taken" — the allowlist stays hidden.
    * **Not in mode `login_identifier="email"`**: there the name is the address and follows it.
    * **Alongside LDAP only as operator** (`by_operator=True`, since 2026-09-27): there the
      names come from the directory; an account that renames itself could adopt the name of a
      person who has never signed in, and lock them out."""
    account = self.store.get_user(user_id)
    if not account:
        raise ValueError(self.t("api.not_found"))
    if self.cfg.login_identifier == "email":
        raise ValueError(self.t("api.username_follows_email"))
    # Alongside LDAP nobody renames themselves (PO decision 2026-09-27): a local account
    # could adopt the directory name of a person who has never signed in, and
    # thereby lock them out — the same gap as open registration. The operator may.
    if self.cfg.ldap_enabled and not by_operator:
        raise ValueError(self.t("api.username_from_directory"))
    name = str(new_username or "").strip()
    if not name:
        raise ValueError(self.t("err.username_required"))
    if len(name) > self.NAME_MAX or name_invalid(name):
        raise ValueError(self.t("err.username_invalid"))
    own = norm_email(account["email"]) if account["email"] and account["email_verified"] else None
    if "@" in norm_identifier(name) and norm_email(name) != own:
        raise ValueError(self.t("api.username_is_address"))
    if name == account["username"]:
        return name
    permitted = {norm_identifier(i) for i in (self.cfg.admin_identifiers or []) if str(i).strip()}
    if self.identifier_taken(name, exclude_id=user_id) or norm_identifier(name) in permitted:
        raise ValueError(self.t("api.user_exists"))
    old = account["username"]
    try:
        # Marker and name in one transaction (G2-N) — in between, a sign-in via
        # LDAP/SAML could otherwise still bind the account via the new name.
        self.store.set_username(user_id, name, itself_chosen=not by_operator)
    except sqlite3.IntegrityError:
        # Race: taken between check and write — the database decides.
        raise ValueError(self.t("api.user_exists")) from None
    self.audit("username_changed", name, ip,
               f"old={old} by=operator" if by_operator else f"old={old}")
    self._security_event("username_changed", user_id, old=old, new=name)
    return name


def request_email_change(self, user_id, new_email, base_url):
    """Request the change to a new address: confirmation link to the NEW one. Returns the
    sending function (for `after_response`) — even when the address is taken
    or reserved and no link goes out; `send()` says so with True/False. None only
    for a throttle and for the own, already taken address. `ValueError` for an
    invalid address or without a mailer. If sending fails before it begins (full
    queue), `send.discard()` lets the token expire — as `on_overflow` for
    `after_response` (since 2026-09-27).

    The response to the requester is the same in every case: if the address is already the identifier
    of another account (or is in `admin_identifiers`), no link goes out, and
    that appears only in the audit log — otherwise the account page would be an oracle for taken
    addresses. The new address is valid only with the click (`confirm_email_change`), before that
    nothing changes.

    **One branch for every target** (G12b, since 2026-09-26). Until then the request for
    a taken address returned early, and that was visible in three places although the
    response read the same: the notice to the own address came only for a free one, the
    request used up the account's quota only for a free one, and the account page
    named `email_change_taken`. Plus the runtime: one row fewer in the database and
    no sending after the response. Now: first the throttles (for every target), then in every
    case a token and an audit line — for "no" a throwaway token, expired from the start
    (nobody knows the plaintext, `open_token` and redeeming do not see it,
    `gc()` clears it; the pattern of R4-03 for registration) —, then always a sender
    that sends the notice to the own address in every case. The account page shows every
    request as `email_change_requested` (`own_events`)."""
    return self._request_change(user_id, new_email, base_url)


def _request_change(self, user_id, new, base_url, source: str = ""):
    """`request_email_change`, with the source for the path via LDAP/SAML
    (`_address_proven_by_source`). With `quelle` the detail of the audit line begins with
    `account=<id> source=<quelle>` — the same for every result, free like taken. From that the
    database also counts the rejections (`Store.source_mail_since`, attack round 2026-09-26)."""
    account = self.store.get_user(user_id)
    if not account:
        raise ValueError(self.t("api.not_found"))
    # Fold first, then check (like registration and admin API): `x＠evil.test@example.com`
    # is valid raw and, folded, an address with two `@` — it would be the token target, recipient
    # and, after the click, the account's taken address (attack round, finding 3).
    mail = norm_email(new or "") or ""
    if not valid_email(mail):
        raise ValueError(self.t("api.email_invalid"))
    if not self.mail_configured():
        raise ValueError(self.t("api.no_mail"))
    base_url = self._checked_base(base_url)
    if mail == norm_email(account["email"] or "") and account["email_verified"]:
        return None
    # Throttled per ACCOUNT (attack round, finding 3 of self-service): the bucket per target address
    # protects a mailbox, not against scattering — otherwise an account would send mails to arbitrarily
    # many foreign addresses until only the IP throttle brakes (reputation of the sender domain, and
    # every mail is a pretext to click). The same quota as per target address.
    # BEFORE the question "taken?" (G12b): otherwise an account probed taken addresses without
    # quota, and after three probes the link to the own check address revealed whether they
    # were taken.
    if not self.rl.allow(f"change-account:{user_id}", self._sec("mail_per_address_max"),
                         self._sec("mail_per_address_window_sec")):
        self.audit("mail_ratelimit", account["username"], detail=f"email_change account={user_id}")
        return None
    # Bucket of its own (like the registration notice, attack A2): anyone with an account requests the change to a
    # FOREIGN address — in the `mail` bucket it would use up the quota with which
    # the owner of that address sends themselves a sign-in link.
    if not self._mail_destination_ok(mail, "email_change", bucket="change"):
        return None
    # An address from `admin_identifiers` gets no change link (like the name): on an
    # instance without an admin, the owner could easily click "confirm your new address" for their
    # own setup — and the FOREIGN account would afterwards carry the taken allowlist address and
    # be first admin at the next sign-in. The same response as "taken".
    no = ("email_change_taken" if self.identifier_taken(mail, exclude_id=user_id)
            else "email_change_reserved" if self._allowlist_address(mail) else None)
    # The same database work in both cases (G12b): for "no" a token that has already
    # expired when it is created.
    raw = self.create_magic_token("email_change", user_id=user_id, email=mail,
                                  ttl_min=(-1 if no else int(self.cfg.email_change_ttl_min)),
                                  payload={"old": account["email"] or ""})
    url = self.magic_url(raw, base_url, "email_change")
    origin = f"account={int(user_id)} source={source} " if source else ""
    self.audit(no or "email_change_requested", account["username"], detail=f"{origin}new={mail}")
    # The mail names the account: whoever confirms an address should see for WHICH one — otherwise
    # a good-faith click confirms the own address for a foreign account (suspicion from
    # the attack round; mainly concerns the path via LDAP/SAML, where the request does not come from the
    # owner of the address).
    name = str(account["username"])
    old = norm_email(account["email"] or "") if account["email_verified"] else None

    def send() -> bool:
        try:
            return (not no) and self._token_mail(
                raw, mail, self.t("mail.email_change.subject"),
                self.t("mail.email_change.text", name=name, url=url),
                html=self.t("mail.email_change.html", name_html=_html.escape(name), url=url))
        finally:
            # In EVERY case (G12b) — even if no link went out, and even if sending
            # the link failed: the text ("applies only once the link is clicked") is correct
            # always, and its absence would reveal "taken".
            if old and old != mail:
                self._change_request_notice(old, name, mail)

    def discard() -> None:
        """Sending fails before it begins (queue full): the token expires
        immediately, as after a failed sending (B6-12) — a never delivered link would
        otherwise, as an open one, hold up the next until its expiry (`open_token`)."""
        self.store.expire_magic_token(self._token_hash(raw))
    send.discard = discard   # type: ignore[attr-defined]
    return send


def _change_request_notice(self, old, name, new) -> None:
    """Even the REQUEST for an address change goes to the previous, taken address
    (attack round, finding 1): if it comes from a taken-over session, the owner learns of it
    before the link is redeemed — and a password change or "end sessions"
    discards it. **Without a link** (nothing whose base would have to be checked; test_self_service)."""
    if self._mail_destination_ok(old, "email_change_notice", bucket="notice"):
        self.send_mail(old, self.t("mail.email_change_notice.subject"),
                       self.t("mail.email_change_notice.text", name=name, new=new))


def _allowlist_address(self, mail) -> bool:
    """Is this address in `admin_identifiers`?"""
    return norm_email(mail or "") in {norm_email(i) for i in (self.cfg.admin_identifiers or [])
                                      if "@" in str(i)}


def confirm_email_change(self, raw, ip: Optional[str] = None) -> Optional[str]:
    """Redeem the confirmation link. Return: "ok", "taken" (meanwhile the identifier of
    another account; until 0.21.x "vergeben") or None (invalid, expired, used, account
    locked/gone).

    Afterwards the new address is the account's, **with evidence** (the click proved
    the mailbox). In mode `login_identifier="email"` the username moves along if it was the
    old address. Open links to the old address (reset, sign-in link) no longer
    apply — they belonged to a mailbox that no longer belongs to the account. The old address
    gets a notice (ASVS 6.3.7)."""
    data = self.redeem_magic(raw, purpose="email_change")
    if not data or not data.get("user_id"):
        return None
    uid = data["user_id"]
    account = self.store.get_user(uid)
    if not account or account["disabled"]:
        return None
    mail = norm_email(data.get("email") or "")
    if not mail:
        return None
    if self.identifier_taken(mail, exclude_id=uid):
        self.audit("email_change_taken", account["username"], ip, f"new={mail} on_confirmation=1")
        return "taken"
    if self._allowlist_address(mail):     # only got onto the list after the request
        self.audit("email_change_reserved", account["username"], ip, f"new={mail} on_confirmation=1")
        return "taken"
    old = account["email"] or ""
    # Address and (in email mode) the name in ONE transaction: written separately,
    # the new address would stand next to the old name after a failure of the second.
    name_follows = (self.cfg.login_identifier == "email" and bool(old)
                  and norm_email(account["username"]) == norm_email(old))
    try:
        self.store.address_switch(uid, mail, name_follows=name_follows)
    except sqlite3.IntegrityError:
        # Race (G12c): the address has become the identifier of another account between check
        # and write. The same response as above; nothing is changed.
        self.audit("email_change_taken", account["username"], ip,
                   f"new={mail} on_confirmation=1 race=1")
        return "taken"
    self.store.revoke_user_magic_tokens(uid)
    name = self._account_name(uid)
    self.audit("email_changed", name, ip, f"old={old} new={mail}")
    self._security_event("email_changed", uid, old=old, new=mail)
    if old and self.mail_configured():
        def notice():
            self.send_mail(old, self.t("mail.email_changed.subject"),
                           self.t("mail.email_changed.text", mail=mail))
        self._notice_outcome.enqueue(notice)
    return "ok"


def _send_signup_notice(self, email, base_url) -> bool:
    """Notice to the owner of an address with which someone wanted to register again (R4-03).

    With confirmation switched on, registration answers for a taken address
    exactly as for a free one ("confirmation mail is on its way") — otherwise it revealed via
    409 and text which addresses have an account. The real owner gets instead
    this mail: no token, only the way to sign in. Throttled like any mail (R4-04), but
    in a bucket of its own — otherwise it would lock the owner out of their own links (A2).
    """
    base_url = self._checked_base(base_url)
    u = self.store.get_user_by_email(email)
    if not u or u["is_service"] or not self.mail_configured():
        return False
    destination = u["email"]
    if not self._mail_destination_ok(destination, "signup_notice", bucket="notice"):
        return False
    login = f"{base_url}{self.cfg.login_path}"
    self.send_mail(destination, self.t("mail.signup_notice.subject"),
                   self.t("mail.signup_notice.text", login=login),
                   html=self.t("mail.signup_notice.html", login=login))
    return True


def send_login_link(self, email, base_url, next="/", *, app: str = "") -> bool:
    """Send a login link to an email address IF a matching interactive user exists.
    Return only internal — outwardly always the same message (no user enumeration).
    `base_url` is checked (`ConfigError` for a foreign host, see `magic_url`).
    `app` (T-104): the app frame the request stood in (a host or an application id of the configuration) — the token
    carries its host as `frame`, so the page the link opens stands in the same frame; anything unknown is dropped.

    The check comes first — before the account lookup, so that the exception reveals no address.
    Sending goes to the stored address (R4-11), throttled per target (R4-04); a
    failed sending invalidates the token (B6-12).
    """
    base_url = self._checked_base(base_url)
    u = self.store.get_user_by_email(email)
    if not u or u["disabled"] or u["is_service"]:
        return False
    if not self._link_allowed(u["id"]):
        # `magiclink_first_login_only` (T-34): the link would be refused at the door — no mail
        # that leads nowhere. Outwardly the same answer as always (no enumeration).
        self.audit("magic_first_login_only", str(u["username"]), detail="mail not sent")
        return False
    destination = u["email"]
    if not self._mail_destination_ok(destination, "login"):
        return False
    payload = {"next": next}
    frame = self._frame_host(app)
    if frame:
        payload["frame"] = frame    # not "app": that key names the application of an account-API link
    raw = self.create_magic_token("login", user_id=u["id"], email=destination, payload=payload)
    url = self.magic_url(raw, base_url)
    mins = self.cfg.magiclink_ttl_min
    self._token_mail(raw, destination, self.t("mail.login_link.subject"),
                     self.t("mail.login_link.text", mins=mins, url=url),
                     html=self.t("mail.login_link.html", mins=mins, url=url))
    return True


def _frame_app(self, request: Optional[Request]) -> str:
    """The host of the app frame this request names (not the default frame) — "" without one. For the return
    targets a route builds itself (B-8: TOTP setup back to the account page), so they stay framed."""
    frame = self._frame(request) if request is not None else None
    default = getattr(self.cfg, "forward_frame_default", "") or ""
    if not frame or frame["host"] == str(default).strip().lower().rstrip("."):
        return ""
    return frame["host"]


def _own_session_rows(self, user_id, current_hash: Optional[str] = None) -> list:
    """The sessions of an account as the account page lists them — one source for `GET /auth/sessions` and
    `account_overview`. Every row: created_at, last_seen, method, ip, user_agent (cut to 120), current (None
    without a known current session), handle (the session handle, T-105: the target of ending this one session; None
    without one)."""
    out = []
    for s in self.store.list_sessions(user_id):
        out.append({"created_at": s["created_at"], "last_seen": s["last_seen"], "ip": s["ip"],
                    "method": s["method"], "user_agent": (s["user_agent"] or "")[:120],
                    "current": (s["token_hash"] == current_hash) if current_hash else None,
                    "handle": s["public_handle"]})
    return out


def account_overview(self, user, *, base: Optional[str] = None, app_host: Optional[str] = None,
                     request: Optional[Request] = None) -> Optional[dict]:
    """The own account's security state as data (T-91) — what the account page shows, for an application that
    draws its own settings page: the same answer `GET /auth/account.json` gives the session.

    `user`: an account dict (`session_user`, `get_user`); a locked, unknown or service account gives None.
    `base` goes in front of the links (default: `base_url`); `app_host` (a host of `forward_apps` with an app
    frame) adds `app=<host>` to them, so the account page opens framed. `request`: the person's request with its
    session cookie — only then does a session carry `current` (True/False); without it `current` is None.

    Members: `account` (username, display name, `source`: where the account comes from — a list of `local`, `oidc`,
    `saml`, `ldap`, two or more for a mixed account, T-99); `sign_in` — `password` ("set", "unset", "directory" or None when
    passwords are off), `totp` ({enabled, recovery_left, recovery_low} or None), `passkeys` ({count, items} or None),
    `pin` (bool or None); `sessions` ({count, items: created_at, last_seen, method, device, current, handle, end — the
    session handle and the action page that ends this session, T-105, None for the current one}); `programs` —
    `oauth`, `services`, `app_passwords` (lists of {name, created_at, last_used}, None when the feature is off) and
    `api_keys_active` (a number, None when keys are off); `approvals` ({pending} or None); `permissions` ({app, names}:
    the account's permissions for the application whose `apps[id].hosts` name `app_host`, T-101 — None for any other
    host or without one); `links` (the account page
    and its sections, absolute); `actions` (T-105: each own action of the register — `username`, `email`, `password`,
    `pin`, `totp`, `recovery_codes`, `passkeys`, `api_keys`, `app_passwords`, `sessions`, `programs`, `services` — → the
    address of its action page `/auth/act/<name>`, None where not offered). None means "not offered here", `[]` "offered, empty". Never a hash, a secret, a key
    prefix, an address or an id of another object.

    Hand it to the application only for a person signed in by a browser session — in a wrapper in front of an app
    in another language: only for a checked `Remote-Kind: user` with `Remote-Auth: session`, for the account of
    `Remote-Id`, answered with `Cache-Control: no-store`. Changes happen on the account page and its action pages
    only."""
    cfg = self.cfg
    uid = user.get("id") if isinstance(user, dict) else _topbar._field(user, "id")
    row = self.store.get_user(uid) if uid is not None else None
    if row is None or row["disabled"] or row["is_service"]:
        return None
    uid = int(row["id"])
    if base is None:
        base = (security.normalize_base(str(cfg.base_url or "").strip()) or "").rstrip("/")
    frame = self._frame_of(app_host) if app_host else None
    from urllib.parse import quote
    q = f"?app={quote(frame['host'], safe='')}" if frame else ""
    methods = cfg.enabled_methods()
    pw_hash = self.store.get_password_hash(uid)
    password = None
    if "password" in methods:
        password = ("set" if pw_hash else ("directory" if cfg.ldap_enabled else "unset"))
    totp = None
    if cfg.totp_enabled:
        enabled = bool(self.store.has_confirmed_totp(uid))
        # T-94: without recovery codes there is nothing to count — the page offers no code action.
        left = self.recovery_codes_remaining(uid) if enabled and cfg.recovery_codes_enabled else None
        totp = {"enabled": enabled, "recovery_left": left,
                "recovery_low": bool(enabled and left is not None and left <= self._RECOVERY_WARN_THRESHOLD)}
    passkeys = None
    if "passkey" in methods:
        items = [{"name": c["name"], "created_at": c["created_at"], "last_used": c["last_used"]}
                 for c in self.store.list_webauthn(uid)]
        passkeys = {"count": len(items), "items": items}
    pin = bool(self.has_pin(uid)) if cfg.pin_enabled else None
    current = None
    if request is not None:
        # The own cookie, on an application's host also its connection (T-26) — the session of this request.
        s = self._gate_session(request, self._gate_host(request))
        current = s["token_hash"] if s and s["user_id"] == uid else None
    # T-105: the session handle and, for every session but this request's own, the action page that ends it.
    end = (f"{base}/auth/act/session_end?" + (f"app={quote(frame['host'], safe='')}&" if frame else "") + "target="
           if cfg.account_enabled else None)
    sessions = [{"created_at": s["created_at"], "last_seen": s["last_seen"], "method": s["method"],
                 "device": self._coarse_agent(s["user_agent"]), "current": s["current"], "handle": s["handle"],
                 "end": (end + s["handle"]) if end and s["handle"] and s["current"] is not True else None}
                for s in self._own_session_rows(uid, current)]
    oauth = services = None
    if cfg.oauth_enabled:
        oauth = [{"name": d["client_name"], "created_at": d["created_at"], "last_used": d["last_used"]}
                 for d in self._oauth_server().devices(uid)]
        if cfg.oauth_service_clients:
            services = [{"name": s["name"], "created_at": s["created_at"], "last_used": s["last_used"]}
                        for s in self.list_service_clients(uid)]
    app_passwords = None
    if self.app_password_hosts():
        app_passwords = [{"name": p["name"], "created_at": p["created_at"], "last_used": p["last_used"],
                          "expires_at": p["expires_at"]}
                         for p in self.list_app_passwords(uid) if not p["revoked"] and not p["expired"]]
    keys = self.store.count_active_api_keys(uid) if cfg.apikey_enabled else None
    pending = self._approvals_pending(row)
    account = f"{base}/auth/account{q}"
    links = {"account": account if cfg.account_enabled else None}
    # A section's link only where the page has the section (the same conditions as `templates._account`).
    offered = {"sessions": True, "totp": totp is not None, "passkeys": passkeys is not None,
               "devices": oauth is not None, "app_passwords": app_passwords is not None,
               "services": services is not None}
    for key, anchor in self._ACCOUNT_ANCHORS.items():
        links[key] = f"{account}#{anchor}" if cfg.account_enabled and offered[key] else None
    links["approvals"] = f"{base}/auth/approvals{q}" if pending is not None else None
    source = self.store.account_sources([uid]).get(uid, ["local"])
    # T-101: on an application's host (`apps[id].hosts`) the account's permissions for that application.
    app = self._app_of_host(app_host) if app_host else None
    permissions = {"app": app, "names": self.permissions_of(row, app=app)} if app else None
    view = {"account": {"username": row["username"], "display_name": row["display_name"] or row["username"],
                        "source": source},
            "sign_in": {"password": password, "totp": totp, "passkeys": passkeys, "pin": pin},
            "sessions": {"count": len(sessions), "items": sessions},
            "programs": {"oauth": oauth, "services": services, "app_passwords": app_passwords,
                         "api_keys_active": keys},
            "approvals": {"pending": pending} if pending is not None else None,
            "permissions": permissions,
            "links": links}
    # T-105: the action pages, where an application sends a person to change something.
    from . import _actions
    view["actions"] = _actions.links(self, view, base, q)
    return view


def _header_lines_error(self, exc) -> None:
    """The same headers for an `HTTPException` from a TinySesam route.

    The response there is built by the host's exception handler (or Starlette's default) —
    the route class never gets to see it. Both do take over `exc.headers`, though; so
    the headers travel into it there. The 401 from `/auth/admin` without a session is exactly such
    a response.

    `exc.headers` remains an ordinary dict with the keys as the route wrote them.
    A detour via `MutableHeaders` wrote them in lowercase — a host handler with
    `exc.headers["Location"]` then no longer found the redirect and delivered a 307 without
    a target (A1). Hence: ignore case only when looking up, never when writing.
    """
    exc.headers = dict(exc.headers or {})
    self._header_lines_in(_DictHeaderLines(exc.headers))


def _csp_report_line(self, raw: bytes, ip: str) -> int:
    """Log the CSP violations in a report body (`csp_report`, T-52); returns how many were logged.

    Two formats: the Reporting API (`application/reports+json`, a list of `{type: "csp-violation", body}`)
    and the older `report-uri` (`application/csp-report`, `{"csp-report": {...}}`). From each report only
    what says WHAT was blocked WHERE: the directive, the PATH of the page — its query is dropped, sign-in,
    reset and invitation links carry their token there — and of the blocked resource only the origin or the
    keyword (`inline`, `eval`). The values come from anyone who can reach the endpoint: every field is cut
    and filtered, and the log takes at most `_CSP_REPORT_LOG_PER_MINUTE` lines per minute in total."""
    from urllib.parse import urlsplit
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return 0
    bodies = []
    if isinstance(data, dict) and isinstance(data.get("csp-report"), dict):
        r = data["csp-report"]
        bodies.append((r.get("effective-directive") or r.get("violated-directive"), r.get("document-uri"),
                       r.get("blocked-uri"), r.get("disposition")))
    elif isinstance(data, list):
        for item in data[:10]:
            if isinstance(item, dict) and item.get("type") == "csp-violation" and isinstance(item.get("body"), dict):
                b = item["body"]
                bodies.append((b.get("effectiveDirective"), b.get("documentURL"), b.get("blockedURL"),
                               b.get("disposition")))

    def directive(v):
        v = str(v or "").strip().split(" ", 1)[0].lower()
        return v if re.fullmatch(r"[a-z-]{1,40}", v) else "?"

    def page(v):
        # `urlsplit` drops line breaks on its own (WHATWG) — "a\nCSP violation … ip=…" would come back as ONE
        # path with spaces and `=`. Percent-encoding leaves nothing that looks like a field of the line.
        from urllib.parse import quote
        try:
            path = urlsplit(str(v or "")).path
        except ValueError:
            return "?"
        return quote(path[:200], safe="/._~-%") or "?"

    def blocked(v):
        v = str(v or "").strip()
        try:
            u = urlsplit(v)
        except ValueError:
            return "?"
        if u.scheme in ("http", "https", "ws", "wss") and u.netloc:
            return security.for_log(f"{u.scheme}://{u.netloc}"[:120])
        return v.lower() if re.fullmatch(r"[a-z-]{1,20}", v.lower()) else (security.for_log(u.scheme[:20]) or "?")

    logged = 0
    for d, doc, blk, disp in bodies:
        if not self.rl.allow("csp_report:log", self._CSP_REPORT_LOG_PER_MINUTE, 60):
            break
        security.seclog.warning("CSP violation directive=%s page=%s blocked=%s disposition=%s ip=%s",
                                directive(d), page(doc), blocked(blk),
                                "report" if str(disp or "") == "report" else "enforce", ip)
        logged += 1
    return logged


def public_base(self, request: Optional[Request] = None, candidate: str = "") -> str:
    """The public base URL for everything that leaves the house — mail links,
    redirect URIs, SAML metadata. Empty means: there is none, the caller aborts.

    Up to 0.18.0 ten places derived this address from the request themselves — six times as
    `cfg.base_url or str(request.base_url)` (magic link, reset, confirmation, OIDC post-logout,
    OIDC redirect URI, admin invitation), three times for SAML and once in the forward-auth
    redirect. The derived part is the raw `Host` header and thus an input of the
    attacker: whoever triggers "forgot password" for a
    foreign mailbox and sets `Host: attacker.example` in the process, made TinySesam send a real mail with a real reset token whose
    link pointed to the attacker's server (R4-01/R8-4, CWE-644). `trusted_redirect_hosts`
    protected only `?next=`, not this route.

    Now: `base_url` always wins — if it is set, nothing at all comes from the request.
    Otherwise the derived host is checked (`security.own_host`), and only a
    host from `trusted_redirect_hosts` or a loopback address counts as the own.

    **This is the only place where this question is decided.**
    `require_public_base()` and `_checked_base()` both call it and only turn the
    empty result into an error — with the text that fits their caller.
    `_forward_login_url()` also asks here (with its one exception, justified in the docstring
    there). Two versions of the same rule diverged as soon as several
    own names were in play: the routes held `base_url`, the route via the methods
    let the `Host` header choose — and the gap sat exactly in the difference.

    `candidate` allows a route to have a differently derived base checked (SAML
    evaluates `X-Forwarded-Proto/Host` itself) — it is checked by the same rule.

    **The path part belongs to it**, from both sources: `base_url="https://example.com/sso"`
    keeps its prefix, and a derived base takes over the server's `root_path`
    (`security.secure_base`). Without that, an app mounted under a subpath got
    mail links without the prefix — and whoever appends it once more afterwards, links with it four times.
    The result is the **finished** base: nothing is appended to it any more.

    The links sent carry the subpath via this base; the built-in pages and
    redirects since T-15 via `_prefix()`/`browser_path()` — from the same `base_url`.

    Whoever needs a base and must not continue without one takes
    `require_public_base()` — this method here returns "" and leaves the
    decision to the caller. Exactly two places may do that, because both have a viable
    way back: the OIDC post-logout (without a base the provider detour is dropped, the local
    logout runs anyway) and `_forward_login_url()` (without a base the redirect stays
    relative, the browser resolves it against the called host).
    """
    if self.cfg.base_url:
        # The CONFIGURED base also goes through the same form check as the derived one
        # (C-7). Before, it saw only `strip().rstrip("/")`: `https://who:what@auth.example`
        # thus stood in every reset link and every redirect URI, a fragment cut off
        # the appended token. `config_check` already rejects both at construction —
        # this line is the floor beneath it, because a config can still be changed after the
        # constructor.
        base = security.normalize_base(str(self.cfg.base_url))
        if not base:
            raise StateError(
                "base_url is set, but is not a usable base address: "
                f"{str(self.cfg.base_url)!r}. Expected is scheme http/https and a host, "
                "without user info, query or fragment (a subpath is allowed, e.g. "
                "\"https://example.com/sso\"). Nothing is guessed here.")
        return base
    raw = str(candidate or (str(request.base_url) if request is not None else "")).strip()
    base = security.secure_base(raw, self.cfg.trusted_redirect_hosts)
    if not base and raw and security.report_once("public_base:" + _host_from(raw)):
        # Say loudly once why nothing happens — otherwise the operator looks for the error
        # at the mailer. fail2ban reads this logger along, and the forward auth asks here on
        # EVERY anonymous request (one page load is twenty subresources): a
        # storm of identical lines would itself be a finding, so `report_once()` says it
        # once per process and host — the hint about base_url is in the line.
        security.seclog.warning(
            "No trustworthy public host: %s comes from the Host header and "
            "is neither in trusted_redirect_hosts nor loopback. The operation aborts "
            "(otherwise a link to a foreign host would go out). Remedy: set "
            "base_url. This line appears once per host, not per request.",
            security.for_log(raw))
    return base


def require_public_base(self, request: Optional[Request] = None, candidate: str = "") -> str:
    """Like `public_base()`, only without a way back: no checked base → `ConfigError`.

    For every route that puts an absolute address **into foreign hands**: link in a mail,
    redirect URI at the IdP, entity ID in SAML metadata.

    Up to 0.18.x this was solved differently at every place, and two places solved it wrongly:
    `/auth/forgot` and `/auth/magic/request` with a missing base wrote only an
    audit line and **still rendered the success page** — HTTP 200, "mail is on its way",
    no mail. The same response prevents user enumeration, and precisely because of that
    it concealed the total failure here: password reset and magic link were
    broken for all users, visible only in the log. The other places threw `HTTPException(500)` — right
    in the result, but a server error in the middle of the sign-in attempt, although it was already clear at construction
    that it could not work.

    Both are gone. `config_check` makes `base_url` mandatory as soon as one of these routes
    is on — so construction fails before a user clicks "forgot password".
    This method is the second lock for the rest: a config that was changed
    after the constructor (it is read at request time). Then the process aborts with a
    message that says what to enter — not with silent success.
    """
    base = self.public_base(request, candidate)
    if not base:
        raise ConfigError(
            "No trustworthy public address: base_url is empty, and the host "
            "from the request is not established as our own (it is not in "
            "trusted_redirect_hosts and is not a loopback address). Nothing is guessed "
            "from the Host header — it is an input of the requester, and with a "
            "mail to a foreign mailbox that is the attacker (R4-01). Remedy: set base_url "
            "to the public address of this app, e.g. "
            "base_url=\"https://auth.example.com\"; mounted under a subpath, with "
            "prefix (\"https://example.com/sso\").")
    return base


def _checked_base(self, base_url) -> str:
    """Check a base address passed in from OUTSIDE before it goes into a link.

    `public_base()` sits in the routes — but whoever embeds TinySesam often builds their own "forgot
    password" form and then calls `send_password_reset(mail, base)`.
    If this app followed the obvious pattern `str(request.base_url)`, it was fully exposed to R4-01,
    although the built-in route had long been sealed: the check was only
    in the route, not in the method. Therefore every route that sends a link now
    checks its base itself — `magic_url()` and the four senders above it.

    It is **the same one rule** — this method calls `public_base()` and turns the
    empty result into an error, just as `require_public_base()` does for the routes.
    The difference lies only in the text of the exception, which speaks of the passed value:

    * If `cfg.base_url` is set, **it wins unconditionally** — with scheme and path part. The
      passed base does not come into play at all. This also catches the case in which, behind a
      TLS-terminating proxy, `str(request.base_url)` yields an `http://` (the link would
      otherwise silently remain unencrypted) **and** the case of several co-trusted names: until the
      second rework `base_url` won here only if the passed host happened to be
      the same; otherwise `trusted_redirect_hosts` decided. The `Host` header could thus
      still *choose* which of the own names goes into the reset link — exactly the core
      of R4-01, only one level deeper.
    * Without `base_url` the host must come from `trusted_redirect_hosts` or be loopback
      (`security.secure_base`). A path in the base is preserved (app mounted under a
      subpath), a user part in the host is not.
    * Everything else is a foreign name → `ConfigError`. No token, no mail, an error
      that the developer sees on the first attempt — instead of a link that the victim
      clicks.

    **Idempotent**, and that is no subtlety: the four senders check their base before the
    token is issued, `magic_url()` checks it once more, because an app also lands there that
    calls only this one method. The first version appended the path part each time anew
    to a base that already carried it (`secure_base()` has returned it as well since N1) — from
    `https://example.com/portal` became, over four stations,
    `https://example.com/portal/portal/portal/portal/auth/reset?token=…`. The mail went
    out, the recipient clicked, the link was 404: no error, no log line. Therefore
    nothing is appended here any more, and a test sends a base WITH a path through all
    five routes and **counts** the occurrences of the prefix.
    """
    raw = str(base_url or "").strip()
    base = self.public_base(candidate=raw)
    # It is replaced silently — but not noiselessly: whoever passes a different address than the one that
    # ends up in the link has either passed the request through (then that is exactly the
    # protection) or made a mistake (then they would otherwise search for a long time). Once per address, not per
    # request: with this pattern the value comes from the `Host` header.
    #
    # The **whole** base is compared, not just the host (C-5): an app under a
    # subpath that passes `https://auth.example/falsch` while `base_url` is
    # `https://auth.example/sso` previously got no line — same host, so
    # the place stayed silent. Exactly this case (wrong prefix → 404 at the recipient) is the one
    # the CHANGELOG promises to report.
    _comparison = security.normalize_base(raw) or raw.rstrip("/")
    if base and raw and _comparison != base \
            and security.report_once("checked_base:" + _comparison):
        security.seclog.warning(
            "Passed base address %s is replaced by base_url (%s) — base_url is the "
            "operator's commitment and always wins. If the value comes from str(request.base_url), "
            "it is the requester's Host header; that is exactly how a reset link pointed to "
            "a foreign server (R4-01). This line appears once per host, not per request.",
            security.for_log(raw), security.for_log(base))
    if not base:
        # `public_base()` has already logged (once per host). In the text of the exception is
        # the shortened version freed of control characters: the value comes from the requester,
        # and an exception travels into logs and error pages.
        raise ConfigError(
            f"This base address does not go into a sent link: "
            f"{security.for_log(raw)!r}. Allowed "
            "are base_url, a host from trusted_redirect_hosts, and loopback. Whoever takes the base "
            "from the request takes the requester's Host header — with a mail to "
            "a foreign mailbox, that is the attacker's. In a route "
            "auth.public_base(request) returns the checked base (empty = abort).")
    return base


