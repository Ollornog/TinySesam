"""Admin panel as a standalone, mountable router.

    auth.admin_router()                                       # APIRouter, RELATIVE paths
    app.include_router(auth.admin_router(), prefix="/admin")  # freely chosen path
    # or mount on a sub-app / own port / subdomain (host routing of the app)

By default `auth.router()` additionally mounts it under `config.admin_path` (default /auth/admin).
`admin_ui_enabled=False` → only the JSON API (`/api/*`), so the UI can be embedded in an
existing panel. The built-in UI works out its own base URL → runs at any
mount point. Admins only.
"""
from __future__ import annotations
import html
import json
import secrets

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse

from .errors import ConfigError, StateError
from .router import _key_kind, _mail_base, hardened_route
from . import security
from ._vocabulary import audit_line_new
from .store import name_invalid, norm_email, valid_email
from .templates import brand, favicon_link, inject_nonce as _inject_nonce
from .theme import TOKENS


def build_admin_router(auth) -> APIRouter:
    cfg = auth.cfg
    ar = APIRouter(tags=["admin"], route_class=hardened_route(auth))

    def guard(request: Request):
        # Admin + (optional) step-up MFA. Browser page request → redirect to login/reauth;
        # JSON/fetch calls → 401/403 (the panel UI reloads after reauth).
        #
        # CSRF is checked HERE, not per route: two panel routes lacked the check
        # (block key, delete resource) because they read no JSON body, so json_body never
        # got to run. Closing a whole class is more reliable than patching it route by route
        # — the next new route would be open again otherwise.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
        return auth._enforce(request, admin=True, mfa=cfg.admin_require_mfa)

    def owner_protection(me, uid: int):
        """Only an owner may change an owner account (owner model). Otherwise an admin would set a
        new password for the owner and become owner themselves — the protection against deletion
        would then be a door with an open window next to it."""
        destination = auth.store.get_user(uid)
        if destination and destination["is_owner"] and not (me and me.get("is_owner")):
            raise HTTPException(403, auth.t("api.owner_only"))
        return destination

    def log(request: Request, event: str, detail=None):
        """Log an admin action — with actor and IP.

        Without both, the audit log is worthless for the post-mortem: it recorded THAT an
        account was blocked or a password reset, not by whom and from where. With
        several admins that is exactly the question asked afterwards. As with CSRF, this
        lives in one place and not in every route — the next new route inherits it.
        """
        person = auth.current_user(request)
        auth.audit(event, person["username"] if person else None, auth.client_ip(request), detail)

    def other_active_admins(uid: int) -> int:
        """How many active, interactive admins remain if `uid` stops being one?

        Counted are those who can really sign in as admin: not blocked, no
        service account (which has no session, and whose keys never carry the flag, R6-5)."""
        return sum(1 for u in auth.store.list_users()
                   if u["is_admin"] and not u["disabled"] and not u["is_service"]
                   and int(u["id"]) != int(uid))

    def roles_from(b: dict) -> list:
        """`roles` from the body: a list of strings — otherwise 400, and BEFORE any write.

        The database accepts any JSON; a role `1` or `null` was only noticed when logging
        (`','.join`), AFTER roles and admin flag had been written: HTTP 500 without an
        audit line (integration finding 8). A string like `"admin"` was silently split into
        letters by `list()`. If the field is missing (or empty), it means "no roles"."""
        raw = b.get("roles")
        if not raw:
            return []
        if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
            raise HTTPException(400, auth.t("api.invalid", reason="roles"))
        return list(raw)

    def uview(u):
        return {"id": u["id"], "username": u["username"], "display_name": u["display_name"],
                "email": u["email"], "is_admin": bool(u["is_admin"]), "is_owner": bool(u["is_owner"]),
                "is_service": bool(u["is_service"]),
                "roles": json.loads(u["roles"] or "[]"), "disabled": bool(u["disabled"]),
                # Why blocked (boundary b): 1 = confirmation of the address is pending (lifted by
                # the confirmation link), 2 = the operator (only they lift it). Previously both
                # looked the same in the panel — and anyone who took an operator block for a pending
                # confirmation waited for a link that never releases anything.
                "disabled_by": {1: "confirmation", 2: "operator"}.get(int(u["disabled"] or 0)),
                "created_at": u["created_at"]}

    def kview(k):
        return {"id": k["id"], "name": k["name"], "prefix": k["prefix"], "created_at": k["created_at"],
                "last_used": k["last_used"], "expires_at": k["expires_at"], "revoked": bool(k["revoked"]),
                "kind": _key_kind(k)}

    # ---------- Users / service accounts ----------
    @ar.get("/api/users")
    def users(request: Request):
        guard(request)
        return [uview(u) for u in auth.store.list_users()]

    @ar.post("/api/users")
    async def user_create(request: Request):
        guard(request)
        b = await auth.json_body(request)
        username = (b.get("username") or "").strip()
        email = norm_email(b.get("email"))
        if email and not valid_email(email):
            raise HTTPException(400, auth.t("api.email_invalid"))
        # Check across both (finding R4-12): username and e-mail are ONE identifier space —
        # an address that is already another account's username is taken.
        if email and auth.identifier_taken(email):
            raise HTTPException(409, auth.t("api.email_taken"))
        # In e-mail mode the address is the identifier — the username may be omitted.
        if not username and cfg.login_identifier == "email" and not b.get("is_service"):
            username = email or ""
        if not username:
            raise HTTPException(400, auth.t("api.username_req"))
        if name_invalid(username):
            raise HTTPException(400, auth.t("err.username_invalid"))
        if auth.identifier_taken(username):
            raise HTTPException(409, auth.t("api.user_exists"))
        roles = roles_from(b)
        # Service account + admin (R6-2): `is_admin` used to be dropped silently here, yet the
        # roles route could still set the flag afterwards. Such an account cannot
        # sign in, its keys never carry the flag (R6-5) — it only counts as "there is
        # an admin" and thereby closes the first-admin path without anyone being admin.
        # Reject loudly instead of discarding silently: whoever ticks both meant something else.
        if b.get("is_service") and b.get("is_admin"):
            raise HTTPException(400, auth.t("api.service_admin"))
        # Same password rule as at every other place that sets one (finding B2-13): until T-13 the
        # panel accepted any password, even `1` — of all places the path on which the
        # initial passwords of whole teams are created. No password stays allowed (SSO/passkey).
        if not b.get("is_service") and b.get("password"):
            defect = auth.password_policy_error(b["password"], username=username, email=email, api=True)
            if defect:
                raise HTTPException(400, defect)
        try:
            if b.get("is_service"):
                uid = auth.create_service(username, roles=roles, display_name=b.get("display_name"))
            else:
                uid = auth.create_user(username, password=b.get("password") or None,
                                       is_admin=bool(b.get("is_admin")), roles=roles,
                                       display_name=b.get("display_name"), email=email)
        except ConfigError as e:
            # Race (G12c): assigned between the checks above and the creation — same
            # reply as there, instead of a 500.
            raise HTTPException(409, auth.t("api.email_taken" if getattr(e, "field", None) == "email"
                                            else "api.user_exists"))
        log(request, "user_create", f"{username} service={bool(b.get('is_service'))}")
        return {"id": uid}

    @ar.post("/api/users/{uid}/disable")
    async def user_disable(request: Request, uid: int):
        me = guard(request)
        b = await auth.json_body(request)
        disabled = bool(b.get("disabled", True))
        if disabled and uid == me["id"]:
            raise HTTPException(400, auth.t("api.no_self_lock"))
        destination = owner_protection(me, uid)
        if disabled and destination and destination["is_owner"]:
            raise HTTPException(400, auth.t("api.owner_protected"))
        # The effect lives in ONE place, `auth.set_disabled` (PO decision 2026-09-27):
        # operator note (no confirmation link lifts the block, H-18), end sessions,
        # revoke keys, discard open links, audit with the admin as actor. An own
        # admin route of the app calls the same method. What depends on the caller stays here.
        if not auth.set_disabled(uid, disabled):
            raise HTTPException(404, auth.t("api.not_found"))
        return {"ok": True}

    @ar.post("/api/users/{uid}/password")
    async def user_password(request: Request, uid: int):
        owner_protection(guard(request), uid)
        b = await auth.json_body(request)
        if not b.get("password"):
            raise HTTPException(400, auth.t("api.password_req"))
        destination = auth.store.get_user(uid)
        defect = auth.password_policy_error(b["password"], username=destination["username"] if destination else None,
                                      email=destination["email"] if destination else None, api=True)
        if defect:
            raise HTTPException(400, defect)   # B2-13: the admin reset obeys the rule as well
        auth.set_password(uid, b["password"])
        auth.store.delete_user_sessions(uid)   # admin reset → end all sessions (force re-login)
        # Newly bound: failed password attempts and the series block (B2-6) end here — the series
        # COMPLETELY, unlike the self-service reset: here the operator decides, not whoever
        # holds the mailbox. Otherwise the account would still stand at the door after the reset.
        auth.lift_lockout(uid, methods=("password",))
        auth._end_series(uid)
        # An admin resets someone else's password when the account is lost or taken over.
        # If the API keys stayed valid, locking out would only have closed the front door —
        # the key is a second, equivalent sign-in.
        keys = auth._keys_revoked(uid, "admin_password_reset")
        # And open links — an address change from the taken-over session goes with it (finding 1).
        auth.store.revoke_user_magic_tokens(uid)
        log(request, "user_password_reset", f"uid={uid} api_keys_revoked={keys}")
        return {"ok": True, "api_keys_revoked": keys}

    @ar.post("/api/users/{uid}/roles")
    async def user_roles(request: Request, uid: int):
        me = guard(request)
        b = await auth.json_body(request)
        destination = owner_protection(me, uid)
        if destination is None:
            raise HTTPException(404)
        roles = roles_from(b)          # checked BEFORE any write, like R6-1 below
        if "is_admin" in b:
            new = bool(b["is_admin"])
            if not new and destination["is_owner"]:
                raise HTTPException(400, auth.t("api.owner_protected"))
            if new and destination["is_service"]:
                raise HTTPException(400, auth.t("api.service_admin"))      # R6-2, see user_create
            # Do not strip the last admin (R6-1). Without an admin the first-admin
            # path opens again: a new one-time token is created, and whoever reads it — in the log,
            # in the console — becomes admin. The panel is then unreachable for anyone
            # who could turn it back. Checked BEFORE any write, so the roles
            # are not left half set.
            if not new and destination["is_admin"] and not other_active_admins(uid):
                raise HTTPException(400, auth.t("api.last_admin"))
        # Before/after in the log (R6-7): "uid=5" said THAT rights changed, not
        # which. Whether someone became admin is exactly the question after an incident.
        # `str` per role: legacy data from before the check (or from own code) must not
        # blow up the line — it is written AFTER the write, and an error here meant
        # "changed, but not logged" (integration finding 8).
        before = destination
        roles_before = sorted(map(str, auth.user_roles(before))) if before else []
        admin_before = bool(before["is_admin"]) if before else False
        auth.set_roles(uid, roles)
        # Write only on a REAL change (H-5): the panel sends the tick with every
        # save of the roles. `set_admin(True)` then wrote a 1 over the 2 of a flag granted by the
        # identity provider — the revocable flag silently became a permanent
        # admin right, and the next login without the admin group no longer removed it (attack on H-5).
        if "is_admin" in b and bool(b["is_admin"]) != bool(destination["is_admin"]):
            auth.store.set_admin(uid, bool(b["is_admin"]))
        afterwards = auth.store.get_user(uid)
        roles_afterwards = sorted(map(str, auth.user_roles(afterwards))) if afterwards else []
        admin_afterwards = bool(afterwards["is_admin"]) if afterwards else False
        detail = (f"uid={uid} roles={','.join(roles_before) or '-'}"
                  f"->{','.join(roles_afterwards) or '-'}")
        if admin_before != admin_afterwards:
            detail += f" admin={int(admin_before)}->{int(admin_afterwards)}"
        log(request, "user_roles", detail)
        return {"ok": True}

    # ---------- Passkeys of other accounts / delete account (B5-08) ----------
    # Previously only the holder could remove a passkey. If the device is stolen and the
    # person locked out, the operator was left with the database. Same for deleting an
    # account: blocking worked, deleting (e.g. on request under Art. 17 GDPR) did not.
    @ar.get("/api/users/{uid}/passkeys")
    def user_passkeys(request: Request, uid: int):
        guard(request)
        return [{"id": c["id"], "name": c["name"], "created_at": c["created_at"],
                 "last_used": c["last_used"]} for c in auth.store.list_webauthn(uid)]

    @ar.post("/api/users/{uid}/passkeys/{cid}/delete")
    def user_passkey_delete(request: Request, uid: int, cid: int):
        owner_protection(guard(request), uid)
        # Through the same path as self-service (integration finding 3): delete, audit line
        # under the holder (the admin as actor=, so `tinysesam audit --user <holder>`
        # finds the revocation) and `passkey_removed` to `on_security_event` — the holder learns
        # that a factor was taken from them, even if someone else did it.
        if not auth.remove_passkey(uid, cid):
            raise HTTPException(404, auth.t("api.not_found"))
        return {"ok": True}

    @ar.post("/api/users/{uid}/owner")
    async def user_owner(request: Request, uid: int):
        """Grant or give up the owner role — only an owner may do that."""
        me = guard(request)
        if not me.get("is_owner"):
            raise HTTPException(403, auth.t("api.owner_only"))
        b = await auth.json_body(request)
        try:
            if not auth.set_owner(uid, bool(b.get("owner", True))):
                raise HTTPException(404, auth.t("api.not_found"))
        except StateError:
            raise HTTPException(400, auth.t("api.last_owner"))
        except ConfigError:
            raise HTTPException(400, auth.t("api.owner_inactive"))
        return {"ok": True}

    @ar.post("/api/users/{uid}/username")
    async def user_username(request: Request, uid: int):
        """Rename someone else's account (G13) — until then neither panel nor CLI could, and
        an identifier collision in existing data could only be resolved from the embedding service.

        Same path as self-service (`change_username`: free in names AND addresses, no
        control characters, no foreign address name, no allowlist name, not in mail mode), but
        as operator: the "self-chosen" marker (G2-N) is dropped, the audit line says
        `by=operator` and carries the admin as `actor=` — `change_username` writes it
        itself, a second one via `log()` would be doubled. An owner account is renamed only by an
        owner (like password, keys, passkeys)."""
        owner_protection(guard(request), uid)
        b = await auth.json_body(request)
        if auth.store.get_user(uid) is None:
            raise HTTPException(404, auth.t("api.not_found"))
        raw = b.get("username")
        if not isinstance(raw, str):
            raise HTTPException(400, auth.t("err.username_required"))
        try:
            new = auth.change_username(uid, raw, auth.client_ip(request), by_operator=True)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"ok": True, "username": new}

    @ar.post("/api/users/{uid}/delete")
    def user_delete(request: Request, uid: int):
        me = guard(request)
        if uid == me["id"]:
            raise HTTPException(400, auth.t("api.no_self_delete"))
        destination = owner_protection(me, uid)
        if destination and destination["is_owner"]:
            raise HTTPException(409, auth.t("api.owner_protected"))
        try:
            if not auth.delete_user(uid):
                raise HTTPException(404, auth.t("api.not_found"))
        except StateError:
            raise HTTPException(409, auth.t("api.last_admin_delete"))
        return {"ok": True}

    # ---------- API keys (per user) ----------
    @ar.get("/api/users/{uid}/keys")
    def user_keys(request: Request, uid: int):
        guard(request)
        return [kview(k) for k in auth.list_api_keys(uid)]

    @ar.post("/api/users/{uid}/keys")
    async def user_key_create(request: Request, uid: int):
        person = guard(request)
        owner_protection(person, uid)
        # Same rule as on the self-service route (`_only_with_session`, R6-6):
        # keys are issued by a human, not by a key. It was missing here — the panel path was
        # the detour on which a key mints a new key, for ANY account.
        # Today R6-5 already holds (a machine key carries no admin flag, a human key
        # is only valid alongside the session); this line does not depend on that staying so.
        if person.get("_via") != "session":
            raise HTTPException(403, auth.t("api.key_needs_session"))
        b = await auth.json_body(request)
        # The audit line is written by `create_api_key` — with owner, IP and actor= (B5-04/R6-3).
        # `create_api_key` raises `ConfigError` for a scope without a valid role and for
        # "unlimited" without permission; an unusable number is a `ValueError`. Uncaught,
        # that was an HTTP 500 (R6-8) — the admin saw "internal server error" instead of the reason.
        try:
            return auth.create_api_key(uid, name=b.get("name"), expires_days=b.get("expires_days"),
                                       roles=b.get("roles"))
        except (ConfigError, ValueError, TypeError) as e:
            raise HTTPException(400, auth.t("api.invalid", reason=str(e)))

    @ar.post("/api/keys/{kid}/revoke")
    def key_revoke(request: Request, kid: int):
        me = guard(request)
        owner = auth.store.api_key_owner(kid)
        if owner is not None:
            owner_protection(me, owner)     # an owner's keys are revoked only by an owner
        # The audit line is written by `revoke_api_key` — with owner, IP and actor= (B5-04/R6-3).
        auth.revoke_api_key(kid)
        return {"ok": True}

    # ---------- Sessions ----------
    @ar.get("/api/sessions")
    def sessions(request: Request):
        guard(request)
        # Reading is logged too (B5-12): the list names IP and sign-in method of every
        # user, and an admin reading along should leave a trace themselves.
        log(request, "sessions_read")
        names = {u["id"]: u["username"] for u in auth.store.list_users()}
        # `full` is the HANDLE (sha256 of the token), not the token: it names the session for
        # ending it and is useless for signing in. Before, the real session token of every
        # user stood here — anyone who saw the panel reply could take over any other session.
        return [{"full": s["token_hash"], "user": names.get(s["user_id"], s["user_id"]), "method": s["method"],
                 "ip": s["ip"], "created_at": s["created_at"], "mfa_ok": bool(s["mfa_ok"])}
                for s in auth.store.list_sessions()]

    @ar.post("/api/sessions/revoke")
    async def session_revoke(request: Request):
        me = guard(request)
        b = await auth.json_body(request)
        # An owner's sessions are ended only by an owner (owner model) — otherwise an admin would sign
        # the owner out as often as they liked.
        if b.get("token"):
            line = auth.store._one("SELECT user_id FROM session WHERE token_hash=?", (str(b["token"]),))
            if line is not None:
                owner_protection(me, int(line["user_id"]))
            auth.store.delete_session_by_handle(b["token"])
        elif b.get("user_id"):
            owner_protection(me, int(b["user_id"]))
            auth.store.delete_user_sessions(int(b["user_id"]))
        log(request, "session_revoke", f"user_id={b.get('user_id')}" if b.get("user_id") else "one session")
        return {"ok": True}

    # ---------- Invitations (magic invite) ----------
    if cfg.magiclink_enabled:
        @ar.post("/api/invite")
        async def invite(request: Request):
            guard(request)
            b = await auth.json_body(request)
            email = (b.get("email") or "").strip()
            # The invitation link goes by mail to a third party and carries a valid
            # token — it must never be built from the Host header (R4-01).
            base = _mail_base(auth, request)
            # Same check as on creation: the roles only land in the account on redemption —
            # a broken role would then fall at the invitee's feet, not the admin's.
            res = auth.create_invite(email or None, base, roles=roles_from(b),
                                     is_admin=bool(b.get("is_admin")), ttl_min=b.get("ttl_min"))
            return {"url": res["url"], "emailed": bool(email and auth.mail_configured())}

    # ---------- Shared resource secrets ----------
    if cfg.resource_locks_enabled:
        @ar.get("/api/resources")
        def resources(request: Request):
            guard(request)
            return [{"name": r["name"], "kind": r["kind"], "label": r["label"], "created_at": r["created_at"]}
                    for r in auth.list_resource_secrets()]

        @ar.post("/api/resources")
        async def resource_set(request: Request):
            guard(request)
            b = await auth.json_body(request)
            name = (b.get("name") or "").strip()
            if not name or not b.get("secret"):
                raise HTTPException(400, auth.t("api.name_secret_req"))
            try:
                auth.set_resource_secret(name, b["secret"], kind=b.get("kind") or "pin", label=b.get("label"))
            except ValueError as e:
                raise HTTPException(400, str(e))
            log(request, "resource_set", name)
            return {"ok": True}

        @ar.post("/api/resources/{name}/delete")
        def resource_delete(request: Request, name: str):
            guard(request)
            auth.remove_resource_secret(name)
            log(request, "resource_delete", name)
            return {"ok": True}

    # ---------- Hardening / audit ----------
    @ar.get("/api/security")
    def security_get(request: Request):
        guard(request)
        return auth.all_security()

    @ar.post("/api/security")
    async def security_set(request: Request):
        me = guard(request)
        # Only an owner changes the hardening values (PO decision 2026-09-24). Otherwise an
        # admin could tighten the block (`max_login_attempts=1`, `account_max_consecutive_failures=10`) and
        # with a few failed attempts under the owner's name lock out exactly the one the
        # owner model is meant to protect — a detour around "an owner cannot be blocked". Any
        # admin may read. If there is no owner yet (existing data with only identity-provider admins),
        # nobody needs protecting: then any admin as before, otherwise the value would be unreachable.
        if not me.get("is_owner") and auth.store.owner_count() > 0:
            raise HTTPException(403, auth.t("api.owner_settings"))
        # Before/after (R6-7): whoever sets `max_login_attempts` from 5 to 5000 effectively
        # switches the block off — the log used to say only THAT something was saved.
        before = auth.all_security()
        values = await auth.json_body(request)
        # Check ALL first, then write: an invalid value in the middle otherwise left
        # half saved behind. And without bounds a typo could paralyse the instance
        # (`rate_limit_max=0` blocks every sign-in, also the one to turn it back — R6-4).
        try:
            checked = {k: security.check_hardening(k, v) for k, v in values.items()}
        except ValueError as e:
            raise HTTPException(400, auth.t("api.invalid", reason=str(e)))
        for k, v in checked.items():
            auth.set_security(k, v)
        afterwards = auth.all_security()
        changed = [f"{k}={before[k]}->{afterwards[k]}" for k in sorted(afterwards)
                     if before.get(k) != afterwards[k]]
        log(request, "security_update", " ".join(changed) or "unchanged")
        return afterwards

    @ar.get("/api/version")
    def version_get(request: Request):
        guard(request)
        return {"version": auth.version()}

    @ar.get("/api/audit")
    def audit(request: Request, limit: int = 100):
        guard(request)
        log(request, "audit_read", f"limit={limit}")    # B5-12, see sessions_read
        # Always the English spelling: a row that an older version wrote after a rollback carries the
        # old event names and keys (`_vocabulary.audit_line_new`).
        lines = [audit_line_new(a) for a in auth.store.recent_audit(limit)]
        return [{"ts": a["ts"], "event": a["event"], "username": a["username"], "ip": a["ip"], "detail": a["detail"]}
                for a in lines]

    # ---------- built-in UI (optional) ----------
    if cfg.admin_ui_enabled:
        @ar.get("", response_class=HTMLResponse)
        def admin_page(request: Request):
            guard(request)
            warn = ""
            if cfg.https_mode == "warn" and not auth._is_secure(request):
                warn = f"<div class=warnbar>{_WARN_HTTP.get(cfg.lang) or _WARN_HTTP['en']}</div>"
            # mount point → relative API base
            # Same CSP as every other built-in page (R8-1). Until 0.19.0, of all pages the
            # panel that creates accounts and grants rights came without CSP and without protection against
            # embedding. Only possible once the inline handlers were gone (`data-on`).
            nonce = secrets.token_urlsafe(16)
            # `__TS_P__` in the header (app, logout) becomes the mount prefix (T-15); the API base `B`
            # comes from the request path and already carries it.
            page_html = render_panel(auth, request.url.path.rstrip("/"), warn=warn, prefix=auth._prefix(request))
            resp = HTMLResponse(_inject_nonce(page_html, nonce))
            policy = auth._csp_header(nonce)
            if policy:
                resp.headers.setdefault("Content-Security-Policy", policy)
            # Adopt an EXISTING cookie, do not overwrite — same treatment as
            # in `render_page`. This place was the third setter and the last that
            # re-rolled on every request: whoever opened the panel in a second tab thereby invalidated
            # the form in the first, and the POST there answered 403 without
            # explanation. This never protected against an attacker — it hit the user's own
            # user. (Was postponed to "after 1.0" as B-1; through the new CSRF checks in the
            # panel it now hits more paths than when it was reported.)
            # Since 0.20.1 via `ensure_csrf()` — same check, same attributes as everywhere.
            auth.ensure_csrf(request, resp)
            return resp

    return ar


#: Warning bar for an unencrypted connection (`https_mode="warn"`). No key in `messages.py` yet,
#: so the two languages live here; other `config.lang` values fall back to English.
_WARN_HTTP = {
    "en": "⚠ Unencrypted (no HTTPS) — credentials are sent in clear text. "
          "Only use on a trusted network or put HTTPS in front.",
    "de": "⚠ Unverschlüsselt (kein HTTPS) — Zugangsdaten gehen im Klartext. "
          "Nur im vertrauenswürdigen Netz nutzen oder HTTPS davorschalten.",
}

#: All panel texts. The panel builds its UI in the browser, so they travel as
#: JSON (`const L`) instead of being inserted into the template text. One key per entry,
#: translated via `auth.t()` — the same table as login, account and error pages.
_KEYS = (
    "locale app tab.users tab.sessions tab.security tab.audit new_user create save saved "
    "f.username f.email f.email_optional f.password f.roles f.admin f.service "
    "f.key_name f.key_expires "
    "th.user th.email th.type th.roles th.status th.actions th.method th.ip th.since th.mfa "
    "th.time th.event th.detail "
    "active disabled disabled_confirmation revoked enable disable "
    "btn.pw btn.rename btn.roles btn.keys btn.passkeys btn.delete btn.owner_on btn.owner_off "
    "passkeys no_passkeys confirm.delete confirm.pk_delete confirm.owner_on confirm.owner_off "
    "err.email err.generic confirm.disable confirm.enable confirm.revoke "
    "prompt.pw prompt.username pw_set roles_groups no_roles api_keys create_key last_used expires "
    "never_expires revoke key_once end_session hardening hardening_owner version installed update_note"
).split()


def panel_texts(auth) -> dict:
    """The panel texts in the language of the running config. `cancel`/`logout` are shared by all
    pages, so they carry no `admin.` prefix."""
    texts = {k: auth.t(f"admin.{k}") for k in _KEYS}
    texts["cancel"] = auth.t("cancel")
    texts["logout"] = auth.t("logout")
    return texts


def render_panel(auth, base: str, warn: str = "", prefix: str = "") -> str:
    """Panel HTML for a given API base. The only place where `_PAGE` is filled —
    so that e.g. a demo/preview embedding shows the same UI as the real panel.

    The language comes from `cfg.lang`, as with every other built-in page. Whoever switches it per
    request (`?lang=`) gets the panel delivered translated.
    """
    cfg = auth.cfg
    # `__TS_P__` first and only in the scaffold — mark, warning and header/footer come after (T-15).
    return (_PAGE.replace("__TS_P__", prefix).replace("__TOKENS__", TOKENS)
            .replace("__BRANDHEAD__", getattr(cfg, "brand_head", "") or "")
            .replace("__HEADER__", brand(getattr(cfg, "brand_header", ""), auth))
            .replace("__FOOTER__", brand(getattr(cfg, "brand_footer", ""), auth))
            # `rp_name` is text, not markup (R8-3) — the other pages have long escaped it.
            # `base` comes from the request path and lands in a JS string; json.dumps plus
            # `<` masking holds it there.
            .replace("__RP__", html.escape(cfg.rp_name))
            .replace('"__BASE__"', json.dumps(base).replace("<", "\\u003c"))
            .replace("__ICON__", favicon_link(getattr(cfg, "brand_icon", "")))
            .replace("__WARN__", warn).replace("__CSRFCK__", auth.csrf_cookie_name)
            .replace("__ROLES__", json.dumps(list(cfg.available_roles)))
            .replace("__REQMAIL__", "true" if (cfg.signup_require_email or
                                              cfg.login_identifier == "email") else "false")
            .replace("__LANG__", cfg.lang)
            # `ensure_ascii=False`: the page is UTF-8, „Härtung" belongs in as „Härtung",
            # not as `Härtung`. Only `<` is masked — an own translation
            # (`add_messages`) with "</script>" would otherwise end the script block.
            .replace("__I18N__",
                     json.dumps(panel_texts(auth), ensure_ascii=False).replace("<", "\\u003c"))
            .replace("__BRANDCSS__", getattr(cfg, "brand_css", "") or ""))


_PAGE = r"""<!doctype html><html lang=__LANG__><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">__ICON__<title>__RP__ — Admin</title>
<style>
__TOKENS__
/* Everything is scoped to .tsadmin — otherwise it bleeds onto brand_header/brand_footer. */
*{box-sizing:border-box}
body{font-family:var(--ts-font);margin:0;background:var(--ts-bg);color:var(--ts-ink);
  min-height:100vh;display:flex;flex-direction:column}
.tsadmin{flex:1}
.tsadmin .warnbar{background:var(--ts-warn-bg);color:var(--ts-warn-ink);padding:8px 20px;font-size:13px;
  border-bottom:1px solid var(--ts-warn-line)}
.tsadmin header{padding:14px 20px;background:var(--ts-surface);border-bottom:1px solid var(--ts-line);
  display:flex;gap:14px;align-items:center}
.tsadmin header h1{font-size:17px;margin:0}
.tsadmin a{color:var(--ts-link);text-decoration:none}
.tsadmin .tabs{display:flex;gap:6px;padding:12px 20px 0;flex-wrap:wrap}
.tsadmin .tab{padding:7px 13px;border-radius:8px 8px 0 0;background:var(--ts-surface);cursor:pointer;
  font-size:14px;border:1px solid transparent;border-bottom:none}
.tsadmin .tab.on{background:var(--ts-surface-2);border-color:var(--ts-line);color:var(--ts-link)}
.tsadmin .wrap{max-width:1000px;margin:0 auto;padding:18px 20px}
.tsadmin table{width:100%;border-collapse:collapse;font-size:13px}
.tsadmin th{text-align:left;color:var(--ts-muted);font-weight:600}
.tsadmin td,.tsadmin th{padding:7px 8px;border-bottom:1px solid var(--ts-line-soft);white-space:nowrap}
.tsadmin button{cursor:pointer;background:var(--ts-accent);color:var(--ts-accent-ink);border:0;
  border-radius:6px;padding:6px 11px;font-size:13px}
.tsadmin button.sec{background:var(--ts-neutral);color:var(--ts-neutral-ink)}
.tsadmin button.warn{background:var(--ts-danger);color:#fff}
.tsadmin button.ok{background:var(--ts-success);color:#fff}
.tsadmin input,.tsadmin select{background:var(--ts-field-bg);color:var(--ts-ink);
  border:1px solid var(--ts-field-line);border-radius:6px;padding:6px 9px;font-size:13px}
.tsadmin .badge{padding:1px 7px;border-radius:20px;font-size:11px;font-weight:600;
  background:var(--ts-chip);color:var(--ts-muted)}
.tsadmin .badge.red{background:var(--ts-err-bg);color:var(--ts-err-ink)}
.tsadmin .badge.grn{background:var(--ts-ok-bg);color:var(--ts-ok-ink)}
.tsadmin .badge.svc{background:var(--ts-info-bg);color:var(--ts-info-ink)}
.tsadmin .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0}
.tsadmin .card{background:var(--ts-surface);border:1px solid var(--ts-line);
  border-radius:calc(var(--ts-radius) - 2px);padding:14px;margin-bottom:14px}
.tsadmin h2{font-size:13px;color:var(--ts-muted);text-transform:uppercase;letter-spacing:.05em;margin:0 0 10px}
.tsadmin .muted{color:var(--ts-muted)}
.tsadmin .w120{width:120px}.tsadmin .w150{width:150px}.tsadmin .w200{width:200px}
.tsadmin .w230{width:230px}.tsadmin .w280{width:280px}.tsadmin .mr12{margin-right:12px}
.tsadmin .small{font-size:12px}
.tsadmin code{background:var(--ts-field-bg);border:1px solid var(--ts-field-line);border-radius:5px;
  padding:2px 6px;font-size:12px}
__BRANDCSS__
</style>__BRANDHEAD__</head><body>
__HEADER__
<div class=tsadmin>
__WARN__
<header><h1>🧠 __RP__ · Admin</h1><a href="__TS_P__/" id=applink>← App</a><a href="__TS_P__/auth/logout" id=outlink>Logout</a></header>
<div class=tabs id=tabs></div>
<div class=wrap id=view></div>
<script>
const B="__BASE__";                                    // mount point (freely chosen) → relative API calls
const ROLES=__ROLES__;                                 // known roles/groups (config.available_roles)
const REQMAIL=__REQMAIL__;                             // config.signup_require_email (e-mail required)
const L=__I18N__;                                      // texts in config.lang — see messages.py
document.getElementById("applink").textContent="← "+L.app;
document.getElementById("outlink").textContent=L.logout;
const TABS=[["users",L["tab.users"]],["sessions",L["tab.sessions"]],["security",L["tab.security"]],["audit",L["tab.audit"]]];
let cur="users";
const g=(u)=>fetch(B+u).then(r=>r.json());
function tsCsrf(){return (document.cookie.match(/(?:^|; )__CSRFCK__=([^;]+)/)||[])[1]||''}
// A rejection (4xx/5xx) ALWAYS comes back as {detail:"<text>"}, even without a JSON body. Before,
// p() only saw the body: savesec reported "saved" although the server said 400, pw "password
// set" despite a rejected rule, saveroles silently reloaded (integration finding 10).
const p=(u,b)=>fetch(B+u,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":tsCsrf()},body:JSON.stringify(b||{})})
  .then(async r=>{let j=null;try{j=await r.json()}catch(e){}
    if(r.ok)return j||{};
    return {detail:(j&&typeof j.detail==="string"&&j.detail)||L["err.generic"]}});
// Show the reason for a rejection — true if there was one. Every action that calls p() goes through
// here (a test pins that), so the next new action does not fail silently again.
const rejected=r=>{if(r&&r.detail){alert(r.detail);return true}return false};
const esc=s=>(s??"").toString().replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
// A button gets its action as data-on (name) and data-a (arguments as JSON), never as
// onclick. Two reasons: the panel's CSP allows script only via nonce, so an inline handler
// would not run at all (R8-1). And data in an onclick is code — the browser decodes the
// attribute and runs the JS parser over it; &#39; became an apostrophe again, and
// a username like  bob');alert(document.cookie);//  ran in the administrator's browser.
// data-a, by contrast, is only read with JSON.parse: whatever is in there stays a value.
const on=(f,...a)=>`data-on="${f}" data-a="${esc(JSON.stringify(a))}"`;
const dt=t=>t?new Date(t*1000).toLocaleString(L.locale):"—";
function tabs(){document.getElementById("tabs").innerHTML=TABS.map(([k,l])=>`<div class="tab ${k==cur?'on':''}" ${on("go",k)}>${esc(l)}</div>`).join("")}
function go(k){cur=k;tabs();({users:users,sessions:sessions,security:security,audit:audit})[k]()}
const V=h=>document.getElementById("view").innerHTML=h;

async function users(){
  const us=await g("/api/users");
  V(`<div class=card><h2>${esc(L.new_user)}</h2><div class=row>
    <input id=nu placeholder="${esc(L["f.username"])}"><input id=ne type=email placeholder="${esc(REQMAIL?L["f.email"]:L["f.email_optional"])}">
    <input id=np type=password placeholder="${esc(L["f.password"])}">
    <input id=nr placeholder="${esc(L["f.roles"])}" class=w200>
    <label><input type=checkbox id=na> ${esc(L["f.admin"])}</label><label><input type=checkbox id=ns> ${esc(L["f.service"])}</label>
    <button ${on("mkuser")}>${esc(L.create)}</button></div></div>
    <table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.email"])}</th><th>${esc(L["th.type"])}</th><th>${esc(L["th.roles"])}</th><th>${esc(L["th.status"])}</th><th>${esc(L["th.actions"])}</th></tr>`+
    us.map(u=>`<tr><td><b>${esc(u.username)}</b></td>
      <td>${esc(u.email)||'<span class=muted>—</span>'}</td>
      <td>${u.is_owner?'<span class="badge grn">owner</span> ':''}${u.is_admin?'<span class="badge grn">admin</span> ':''}${u.is_service?'<span class="badge svc">service</span>':'<span class=badge>user</span>'}</td>
      <td>${esc((u.roles||[]).join(", "))||'—'}</td>
      <td>${u.disabled?`<span class="badge red">${esc(u.disabled_by==="confirmation"?L.disabled_confirmation:L.disabled)}</span>`:`<span class="badge grn">${esc(L.active)}</span>`}</td>
      <td>
        <button class="${u.disabled?'ok':'warn'}" ${on("dis",u.id,!u.disabled)}>${esc(u.disabled?L.enable:L.disable)}</button>
        <button class=sec ${on("pw",u.id)}>${esc(L["btn.pw"])}</button>
        <button class=sec ${on("ren",u.id,u.username)}>${esc(L["btn.rename"])}</button>
        <button class=sec ${on("roles",u.id,(u.roles||[]).join(','),u.is_admin?1:0)}>${esc(L["btn.roles"])}</button>
        <button class=sec ${on("keys",u.id,u.username)}>${esc(L["btn.keys"])}</button>
        <button class=sec ${on("pks",u.id,u.username)}>${esc(L["btn.passkeys"])}</button>
        <button class=sec ${on("own",u.id,!u.is_owner)}>${esc(u.is_owner?L["btn.owner_off"]:L["btn.owner_on"])}</button>
        <button class=warn ${on("deluser",u.id)}>${esc(L["btn.delete"])}</button>
      </td></tr><tr id=r${u.id}></tr><tr id=k${u.id}></tr>`).join("")+`</table>`);
}
async function mkuser(){const b={username:nu.value,email:ne.value,password:np.value,roles:nr.value.split(",").map(s=>s.trim()).filter(Boolean),is_admin:na.checked,is_service:ns.checked};
  if(REQMAIL&&!ns.checked&&!ne.value.trim())return alert(L["err.email"]);
  const r=await p("/api/users",b);if(!rejected(r))users()}
async function own(id,o){if(!confirm(o?L["confirm.owner_on"]:L["confirm.owner_off"]))return;rejected(await p(`/api/users/${id}/owner`,{owner:o}));users()}
async function dis(id,d){if(!confirm(d?L["confirm.disable"]:L["confirm.enable"]))return;rejected(await p(`/api/users/${id}/disable`,{disabled:d}));users()}
async function pw(id){const v=prompt(L["prompt.pw"]);if(v&&!rejected(await p(`/api/users/${id}/password`,{password:v})))alert(L.pw_set)}
async function ren(id,alt){const v=prompt(L["prompt.username"],alt);if(v&&v!==alt&&!rejected(await p(`/api/users/${id}/username`,{username:v})))users()}
async function roles(id,cur,isadmin){
  const have=new Set((cur||"").split(",").map(s=>s.trim()).filter(Boolean));
  const inner = ROLES.length
    ? ROLES.map(r=>`<label class=mr12><input type=checkbox class="rc_${id}" value="${esc(r)}" ${have.has(r)?"checked":""}> ${esc(r)}</label>`).join("")
    : `<input id="rf${id}" value="${esc(cur)}" placeholder="${esc(L["f.roles"])}" class=w280>`;
  document.getElementById("r"+id).innerHTML=`<td colspan=5><div class=card><h2>${esc(L.roles_groups)}</h2>
    <div class=row>${inner||`<span class=muted>${esc(L.no_roles)}</span>`}</div>
    <div class=row><label><input type=checkbox id="ra${id}" ${isadmin?"checked":""}> ${esc(L["f.admin"])}</label>
      <button ${on("saveroles",id)}>${esc(L.save)}</button>
      <button class=sec ${on("clr",id)}>${esc(L.cancel)}</button></div></div></td>`;
}
async function saveroles(id){
  const roles = ROLES.length
    ? [...document.querySelectorAll(".rc_"+id+":checked")].map(c=>c.value)
    : (document.getElementById("rf"+id).value||"").split(",").map(s=>s.trim()).filter(Boolean);
  rejected(await p(`/api/users/${id}/roles`,{roles,is_admin:document.getElementById("ra"+id).checked}));users();
}
async function keys(id,name){const ks=await g(`/api/users/${id}/keys`);
  document.getElementById("k"+id).innerHTML=`<td colspan=5><div class=card><h2>${esc(L.api_keys)} · ${esc(name)}</h2>
    <div class=row><input id=kn placeholder="${esc(L["f.key_name"])}"><input id=ke type=number placeholder="${esc(L["f.key_expires"])}" class=w150>
    <button ${on("mkkey",id)}>${esc(L.create_key)}</button></div>
    <table>`+ks.map(k=>`<tr><td><code>${esc(k.prefix)}</code> ${esc(k.name||'')}</td><td>${k.revoked?`<span class="badge red">${esc(L.revoked)}</span>`:`<span class="badge grn">${esc(L.active)}</span>`}</td>
      <td>${esc(L.last_used)} ${dt(k.last_used)}</td><td>${k.expires_at?esc(L.expires)+' '+dt(k.expires_at):esc(L.never_expires)}</td>
      <td>${k.revoked?'':`<button class=warn ${on("revk",k.id,id,name)}>${esc(L.revoke)}</button>`}</td></tr>`).join("")+`</table></div></td>`}
async function mkkey(id){const r=await p(`/api/users/${id}/keys`,{name:kn.value,expires_days:ke.value?parseInt(ke.value):null});
  if(!rejected(r)&&r.key)prompt(L.key_once,r.key);keys(id,"")}
async function pks(id,name){const ps=await g(`/api/users/${id}/passkeys`);
  document.getElementById("k"+id).innerHTML=`<td colspan=5><div class=card><h2>${esc(L.passkeys)} · ${esc(name)}</h2>
    <table>`+(ps.length?ps.map(c=>`<tr><td>${esc(c.name||'')}</td><td>${dt(c.created_at)}</td><td>${esc(L.last_used)} ${dt(c.last_used)}</td>
      <td><button class=warn ${on("delpk",id,c.id,name)}>${esc(L.revoke)}</button></td></tr>`).join(""):`<tr><td class=muted>${esc(L.no_passkeys)}</td></tr>`)+`</table></div></td>`}
async function delpk(uid,cid,name){if(confirm(L["confirm.pk_delete"])){rejected(await p(`/api/users/${uid}/passkeys/${cid}/delete`));pks(uid,name)}}
async function deluser(id){if(!confirm(L["confirm.delete"]))return;if(!rejected(await p(`/api/users/${id}/delete`)))users()}
async function revk(kid,uid,name){if(confirm(L["confirm.revoke"])){rejected(await p(`/api/keys/${kid}/revoke`));keys(uid,name)}}

async function sessions(){const ss=await g("/api/sessions");
  V(`<table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.method"])}</th><th>${esc(L["th.ip"])}</th><th>${esc(L["th.since"])}</th><th>${esc(L["th.mfa"])}</th><th></th></tr>`+
    ss.map(s=>`<tr><td><b>${esc(s.user)}</b></td><td>${esc(s.method)}</td><td>${esc(s.ip)}</td><td>${dt(s.created_at)}</td>
      <td>${s.mfa_ok?'✓':'—'}</td><td><button class=warn ${on("revs",s.full)}>${esc(L.end_session)}</button></td></tr>`).join("")+`</table>`)}
async function revs(t){rejected(await p("/api/sessions/revoke",{token:t}));sessions()}
function clr(id){document.getElementById("r"+id).innerHTML=""}

async function security(){const s=await g("/api/security");const v=await g("/api/version");
  V(`<div class=card><h2>${esc(L.hardening)}</h2>`+
    Object.entries(s).map(([k,v])=>`<div class=row><label class=w230>${esc(k)}</label><input id="s_${esc(k)}" value="${esc(v)}" type=number class=w120></div>`).join("")+
    `<div class="muted small">${esc(L.hardening_owner)}</div>`+
    `<div class=row><button ${on("savesec",Object.keys(s))}>${esc(L.save)}</button></div></div>`+
    `<div class=card><h2>${esc(L.version)}</h2><div class=row>${esc(L.installed)} <code>${esc(v.version)}</code></div>
     <div class="muted small">${esc(L.update_note)}</div></div>`)}
async function savesec(keys){const b={};keys.forEach(k=>b[k]=parseInt(document.getElementById("s_"+k).value));if(!rejected(await p("/api/security",b)))alert(L.saved)}


async function audit(){const a=await g("/api/audit?limit=120");
  V(`<table><tr><th>${esc(L["th.time"])}</th><th>${esc(L["th.event"])}</th><th>${esc(L["th.user"])}</th><th>${esc(L["th.ip"])}</th><th>${esc(L["th.detail"])}</th></tr>`+
    a.map(e=>`<tr><td>${dt(e.ts)}</td><td>${esc(e.event)}</td><td>${esc(e.username)||'—'}</td><td>${esc(e.ip)||'—'}</td><td>${esc(e.detail)||''}</td></tr>`).join("")+`</table>`)}

// One delegated listener for all buttons, including those loaded later via innerHTML. Only names
// from ACT are callable — data-on selects an action, it does not name arbitrary code.
const ACT={go,mkuser,own,dis,pw,ren,roles,saveroles,clr,keys,mkkey,revk,revs,savesec,pks,delpk,deluser};
document.addEventListener("click",e=>{const el=e.target.closest("[data-on]");
  if(!el||!ACT[el.dataset.on])return;ACT[el.dataset.on](...JSON.parse(el.dataset.a||"[]"))});
tabs();users();
</script>
</div>__FOOTER__</body></html>"""
