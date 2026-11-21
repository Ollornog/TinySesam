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
from . import dialog as _dialog
from . import topbar as _topbar
from .templates import brand, favicon_link, inject_nonce as _inject_nonce
from .theme import TOKENS, c22_css, c22_head, theme_head


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
        person = guard(request)
        b = await auth.json_body(request)
        # An account with a password the admin chose, or with admin rights, is a way in for whoever holds the stale
        # admin session (B-12) — so a fresh confirmation also with `admin_require_mfa=False`, like the password
        # reset and the invitation. An account without either (SSO, passkey, service) gives nobody access yet.
        if b.get("is_admin") or (b.get("password") and not b.get("is_service")):
            auth._require_fresh(request, person)
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
        if b.get("password") and not b.get("is_service") and cfg.admin_password_must_change:
            # T-46 (ASVS 6.4.1): the admin chose this password, so it is a start secret — the first
            # password sign-in asks for an own one.
            auth.store.set_password_must_change(uid, True)
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
        person = guard(request)
        owner_protection(person, uid)
        # A password the admin knows is a way into that account (B-12): only from a fresh confirmation — also with
        # `admin_require_mfa=False`, where the guard above does not ask for one (attack round B).
        auth._require_fresh(request, person)
        b = await auth.json_body(request)
        if not b.get("password"):
            raise HTTPException(400, auth.t("api.password_req"))
        destination = auth.store.get_user(uid)
        defect = auth.password_policy_error(b["password"], username=destination["username"] if destination else None,
                                      email=destination["email"] if destination else None, api=True)
        if defect:
            raise HTTPException(400, defect)   # B2-13: the admin reset obeys the rule as well
        # `by_operator`: a start secret (T-46) — the next password sign-in asks for an own password —
        # and the holder learns of it (T-47: event, mail, and the line below on the account page).
        auth.set_password(uid, b["password"], by_operator=True)
        if destination is not None:
            auth.audit("password_set_by_admin", destination["username"],
                       detail=f"must_change={int(bool(cfg.admin_password_must_change))}")
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
            # Making an account admin hands the panel to whoever holds that account — from a stale admin session
            # an account of the attacker's own (self-registered, invited) would keep the panel after the session
            # ends. New access (B-12): a fresh confirmation, also with `admin_require_mfa=False`.
            if new and not destination["is_admin"]:
                auth._require_fresh(request, me)
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
        auth._require_fresh(request, person)       # a new lasting way in (B-12), whatever admin_require_mfa says
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

    # ---------- Connected programs (OAuth grants, T-36) ----------
    if cfg.oauth_enabled:
        @ar.get("/api/oauth/devices")
        def oauth_devices(request: Request):
            guard(request)
            log(request, "oauth_devices_read")
            return auth._oauth_server().devices()

        @ar.post("/api/oauth/devices/{grant_id}/revoke")
        def oauth_device_revoke(request: Request, grant_id: int):
            me = guard(request)
            g = auth.store.oauth_grant(grant_id)
            if g is None:
                raise HTTPException(404, auth.t("api.not_found"))
            owner_protection(me, int(g["user_id"]))   # an owner's devices are disconnected only by an owner
            # The audit line (`oauth_revoked`, actor=) is written by `revoke_grant`.
            return {"ok": auth._oauth_server().revoke_grant(int(grant_id), "admin", auth.client_ip(request))}

    # ---------- Services: client_credentials + private_key_jwt (T-60, ADR-13) ----------
    if cfg.oauth_enabled and cfg.oauth_service_clients:
        @ar.get("/api/oauth/services")
        def oauth_services(request: Request):
            guard(request)
            log(request, "oauth_services_read")
            return auth.list_service_clients()

        @ar.post("/api/users/{uid}/service-pairing")
        async def service_pairing(request: Request, uid: int):
            person = guard(request)
            owner_protection(person, uid)     # a service acting as an owner is paired only by an owner
            # Same rule as for an API key: issued by a person, never by a key — and, being a new lasting way in
            # (B-12), only from a fresh confirmation.
            if person.get("_via") != "session":
                raise HTTPException(403, auth.t("api.key_needs_session"))
            auth._require_fresh(request, person)
            b = await auth.json_body(request)
            # The audit line (`oauth_pairing_issued`, actor=) is written by `create_service_pairing`.
            try:
                return auth.create_service_pairing(uid, name=b.get("name"), resources=b.get("resources"),
                                                   roles=b.get("roles"))
            except (ConfigError, ValueError, TypeError) as e:
                raise HTTPException(400, auth.t("api.invalid", reason=str(e)))

        @ar.post("/api/oauth/services/{client_id}/revoke")
        def oauth_service_revoke(request: Request, client_id: str):
            me = guard(request)
            svc = auth.store.oauth_service(client_id)
            if svc is None:
                raise HTTPException(404, auth.t("api.not_found"))
            owner_protection(me, int(svc["user_id"]))
            # The audit line (`oauth_service_revoked`, actor=) is written by `revoke`.
            return {"ok": auth.revoke_service_client(client_id)}

    # ---------- App passwords of all accounts (T-66) ----------
    if auth.app_password_hosts():
        @ar.get("/api/app-passwords")
        def app_passwords(request: Request):
            guard(request)
            log(request, "app_passwords_read")
            return auth.list_app_passwords()

        @ar.post("/api/app-passwords/{pw_id}/revoke")
        def app_password_revoke(request: Request, pw_id: int):
            me = guard(request)
            row = auth.store.app_password(pw_id)
            if row is None:
                raise HTTPException(404, auth.t("api.not_found"))
            owner_protection(me, int(row["user_id"]))   # an owner's app passwords are revoked only by an owner
            # The audit line (`app_password_revoke`, actor=) is written by `revoke_app_password`.
            return {"ok": auth.revoke_app_password(pw_id, by_operator=True)}

    # ---------- Invitations (magic invite) ----------
    if cfg.magiclink_enabled:
        @ar.post("/api/invite")
        async def invite(request: Request):
            # An invitation creates an account — possibly an admin — for whoever holds the link: new access
            # (B-12), so a fresh confirmation also with `admin_require_mfa=False` (attack round B).
            auth._require_fresh(request, guard(request))
            b = await auth.json_body(request)
            email = (b.get("email") or "").strip()
            # The invitation link goes by mail to a third party and carries a valid
            # token — it must never be built from the Host header (R4-01).
            base = _mail_base(auth, request)
            # Same check as on creation: the roles only land in the account on redemption —
            # a broken role would then fall at the invitee's feet, not the admin's.
            try:
                res = auth.create_invite(email or None, base, roles=roles_from(b),
                                         is_admin=bool(b.get("is_admin")), ttl_min=b.get("ttl_min"))
            except ConfigError:
                raise                     # a setup error (base address) stays what it was, not an input error
            except ValueError as e:
                # `ttl_min` outside 1…`signin_link_max_ttl_min` or not a number: the admin's input, not a 500.
                raise HTTPException(400, str(e))
            return {"url": res["url"], "emailed": bool(email and auth.mail_configured())}

    # ---------- Sign-in link without mail (T-33) ----------
    # The admin hands an account a one-time link by any channel — no mailer needed. Same token as
    # the mailed link (purpose `login`), so the same rules: single use, second factor
    # (`magiclink_require_second_factor`), discarded on disable and on password reset.
    if cfg.magiclink_enabled:
        @ar.post("/api/users/{uid}/signin-link")
        async def user_signin_link(request: Request, uid: int):
            person = guard(request)
            owner_protection(person, uid)      # an owner's link is issued only by an owner
            # A sign-in link is a credential, like an API key: issued by a human in a session,
            # never by a key (same rule as key creation above, R6-6).
            if person.get("_via") != "session":
                raise HTTPException(403, auth.t("api.link_needs_session"))
            auth._require_fresh(request, person)   # a credential for that account (B-12), even without admin MFA
            b = await auth.json_body(request)
            if auth.store.get_user(uid) is None:
                raise HTTPException(404, auth.t("api.not_found"))
            # The audit line (`signin_link_issue`, admin as actor=) is written by `create_signin_link`.
            try:
                return auth.create_signin_link(uid, ttl_min=b.get("ttl_min"))
            except ConfigError:
                # Only `base_url` builds the address (R4-01) — missing it is the setup, not the input.
                raise HTTPException(503, auth.t("api.base_missing"))
            except ValueError as e:
                raise HTTPException(400, str(e))

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
            me = guard(request)
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
            # The top bar's sign-out form needs the CSRF token now; `ensure_csrf` below sets the same one (T-64).
            page_html = render_panel(auth, request.url.path.rstrip("/"), warn=warn, prefix=auth._prefix(request),
                                     viewer=me, csrf=auth.csrf_token(request) if cfg.csrf_enabled else "")
            resp = HTMLResponse(_inject_nonce(page_html, nonce))
            auth._set_csp(resp, nonce, auth._prefix(request))
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
    "never_expires revoke key_once end_session hardening hardening_owner version installed update_note "
    "btn.link signin_link link_once prompt.link_ttl key_new "
    "tab.devices th.client th.resource th.last disconnect no_devices confirm.disconnect "
    "tab.app_passwords no_app_passwords th.name th.apps expired confirm.revoke_app_password "
    "services no_services pair_service f.service_name pairing_code pairing_once th.key confirm.revoke_service"
).split()


def panel_texts(auth) -> dict:
    """The panel texts in the language of the running config. `cancel`/`logout` are shared by all
    pages, so they carry no `admin.` prefix."""
    texts = {k: auth.t(f"admin.{k}") for k in _KEYS}
    texts["cancel"] = auth.t("cancel")
    texts["logout"] = auth.t("logout")
    # The copy button next to the sign-in link (T-35) speaks like the one in the dialogs.
    for k in ("copy", "copied", "copy_manual"):
        texts[k] = auth.t(f"dlg.{k}")
    return texts


def render_panel(auth, base: str, warn: str = "", prefix: str = "", viewer=None, csrf: str = "") -> str:
    """Panel HTML for a given API base. The only place where `_PAGE` is filled —
    so that e.g. a demo/preview embedding shows the same UI as the real panel.

    `viewer` (the signed-in admin) and `csrf` feed the top bar's account menu (T-64); without a viewer the bar
    shows logo and name only.

    The language comes from `cfg.lang`, as with every other built-in page. Whoever switches it per
    request (`?lang=`) gets the panel delivered translated.
    """
    cfg = auth.cfg
    bar = ""
    if getattr(cfg, "topbar_enabled", True):
        bar = (_topbar.render(auth, viewer=viewer, csrf=csrf, current="admin").replace("__TS_P__", prefix)
               + _topbar.assets())
    # `__TS_P__` first and only in the scaffold — mark, warning and header/footer come after (T-15).
    return (_PAGE.replace("__TS_P__", prefix).replace("__TOKENS__", TOKENS)
            .replace("__THEMEHEAD__", theme_head())
            .replace("__TITLE__", html.escape(auth.t("acc.admin")))
            .replace("__BRANDHEAD__", c22_head(cfg) + (getattr(cfg, "brand_head", "") or ""))
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
            .replace("__LINKS__", "true" if cfg.magiclink_enabled else "false")
            .replace("__LINKTTL__", str(int(cfg.magiclink_ttl_min)))
            .replace("__OAUTH__", "true" if cfg.oauth_enabled else "false")
            .replace("__APPPW__", "true" if auth.app_password_hosts() else "false")
            .replace("__SVC__", "true" if (cfg.oauth_enabled and cfg.oauth_service_clients) else "false")
            .replace("__RESOURCES__", json.dumps([r for r in (cfg.oauth_resources or [])]).replace("<", "\\u003c"))
            .replace("__LANG__", cfg.lang)
            # `ensure_ascii=False`: the page is UTF-8, „Härtung" belongs in as „Härtung",
            # not as `Härtung`. Only `<` is masked — an own translation
            # (`add_messages`) with "</script>" would otherwise end the script block.
            .replace("__I18N__",
                     json.dumps(panel_texts(auth), ensure_ascii=False).replace("<", "\\u003c"))
            .replace("__BRANDCSS__", c22_css(cfg) + (getattr(cfg, "brand_css", "") or ""))
            # Last: the top bar (account name) and the dialog building block (T-35) carry texts of their own; no
            # later replace may touch them.
            .replace("__BAR__", bar)
            .replace("__DIALOG__", _dialog.assets(auth)))


_PAGE = r"""<!doctype html><html lang=__LANG__><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">__THEMEHEAD____ICON__<title>__RP__ — Admin</title>
<style>
__TOKENS__
/* Everything is scoped to .tsadmin — otherwise it bleeds onto brand_header/brand_footer. */
*{box-sizing:border-box}
body{font-family:var(--ts-font);margin:0;background:var(--ts-bg);color:var(--ts-ink);
  min-height:100vh;display:flex;flex-direction:column}
.tsadmin{flex:1}
.tsadmin .warnbar{background:var(--ts-warn-bg);color:var(--ts-warn-ink);padding:8px 20px;font-size:13px;
  border-bottom:1px solid var(--ts-warn-line)}
.tsadmin .tstitle{max-width:1000px;margin:0 auto;padding:20px 20px 4px;font-size:20px;font-weight:600}
.tsadmin a{color:var(--ts-link);text-decoration:none}
.tsadmin .tabs{display:flex;gap:6px;max-width:1000px;margin:0 auto;padding:12px 20px 0;flex-wrap:wrap}
.tsadmin .tab{padding:7px 13px;border-radius:8px 8px 0 0;background:var(--ts-surface);cursor:pointer;
  font-size:14px;border:1px solid transparent;border-bottom:none}
.tsadmin .tab.on{background:var(--ts-surface-2);border-color:var(--ts-line);color:var(--ts-link)}
.tsadmin .wrap{max-width:1000px;margin:0 auto;padding:18px 20px;overflow-x:auto}
/* overflow-x (T-35): the wide user table scrolls inside .wrap instead of widening the page — on a phone the wider
   page widened the layout viewport, and the dialog centred in it sat beside the screen. */
.tsadmin table{width:100%;border-collapse:collapse;font-size:13px}
.tsadmin th{text-align:left;color:var(--ts-muted);font-weight:600}
.tsadmin td,.tsadmin th{padding:7px 8px;border-bottom:1px solid var(--ts-line-soft);white-space:nowrap}
.tsadmin button{cursor:pointer;background:var(--ts-accent);color:var(--ts-accent-ink);border:0;
  border-radius:6px;padding:6px 11px;font-size:13px}
.tsadmin button.sec{background:var(--ts-neutral);color:var(--ts-neutral-ink)}
.tsadmin button.warn{background:var(--ts-danger);color:var(--ts-danger-ink)}
.tsadmin button.ok{background:var(--ts-success);color:var(--ts-success-ink)}
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
.tsadmin img.qr{display:block;margin:10px 0;width:180px;height:180px;background:#fff;padding:6px;border-radius:6px}
.tsadmin code{background:var(--ts-field-bg);border:1px solid var(--ts-field-line);border-radius:5px;
  padding:2px 6px;font-size:12px}
.tsadmin .lkcopy{display:flex;gap:8px;align-items:center}
.tsadmin .lkstate{font-size:12px;color:var(--ts-ok-ink)}
.tsadmin .lkstate.manual{color:var(--ts-warn-ink)}
__BRANDCSS__
</style>__BRANDHEAD__</head><body>
__HEADER__
__BAR__
<div class=tsadmin>
__WARN__
<h1 class=tstitle>__TITLE__</h1>
<div class=tabs id=tabs></div>
<div class=wrap id=view></div>
__DIALOG__
<script>
const B="__BASE__";                                    // mount point (freely chosen) → relative API calls
const ROLES=__ROLES__;                                 // known roles/groups (config.available_roles)
const REQMAIL=__REQMAIL__;                             // config.signup_require_email (e-mail required)
const L=__I18N__;                                      // texts in config.lang — see messages.py
const LINKS=__LINKS__;                                 // config.magiclink_enabled: admin may issue sign-in links
const LINKTTL=__LINKTTL__;                             // config.magiclink_ttl_min: default validity of a link
const OAUTH=__OAUTH__;                                 // config.oauth_enabled: tab "connected programs" (T-36)
const APPPW=__APPPW__;                                 // an application takes app passwords: tab "app passwords" (T-66)
const SVC=__SVC__;                                     // config.oauth_service_clients: pair services (T-60)
const RESOURCES=__RESOURCES__;                         // config.oauth_resources: what a service may be paired for
const TABS=[["users",L["tab.users"]],["sessions",L["tab.sessions"]]].concat(OAUTH?[["devices",L["tab.devices"]]]:[]).concat(APPPW?[["apppw",L["tab.app_passwords"]]]:[]).concat([["security",L["tab.security"]],["audit",L["tab.audit"]]]);
let cur="users";
// H2 (T-45): the panel demands a fresh confirmation (`admin_require_mfa`). A tab left open past the
// window gets 403 + X-TinySesam-Reauth — go to the reauth page and come back here instead of failing.
const reauth=r=>{const re=r.headers&&r.headers.get("X-TinySesam-Reauth");
  if(r.status===403&&re){location.href=re+"?next="+encodeURIComponent(location.pathname);return true}return false};
const g=(u)=>fetch(B+u).then(r=>reauth(r)?new Promise(()=>{}):r.json());
function tsCsrf(){return (document.cookie.match(/(?:^|; )__CSRFCK__=([^;]+)/)||[])[1]||''}
// A rejection (4xx/5xx) ALWAYS comes back as {detail:"<text>"}, even without a JSON body. Before,
// p() only saw the body: savesec reported "saved" although the server said 400, pw "password
// set" despite a rejected rule, saveroles silently reloaded (integration finding 10).
const p=(u,b)=>fetch(B+u,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":tsCsrf()},body:JSON.stringify(b||{})})
  .then(async r=>{let j=null;try{j=await r.json()}catch(e){}
    if(r.ok)return j||{};
    if(reauth(r))return new Promise(()=>{});  // the page is leaving — no "done", no error
    return {detail:(j&&typeof j.detail==="string"&&j.detail)||L["err.generic"]}});
// Show the reason for a rejection — true if there was one. Every action that calls p() goes through
// here (a test pins that), so the next new action does not fail silently again.
// Own dialog (T-35), not the browser's: shown without waiting — the caller only needs the verdict.
const rejected=r=>{if(r&&r.detail){tsAlert(r.detail);return true}return false};
const esc=s=>(s??"").toString().replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
// A button gets its action as data-on (name) and data-a (arguments as JSON), never as
// onclick. Two reasons: the panel's CSP allows script only via nonce, so an inline handler
// would not run at all (R8-1). And data in an onclick is code — the browser decodes the
// attribute and runs the JS parser over it; &#39; became an apostrophe again, and
// a username like  bob');steal(document.cookie);//  ran in the administrator's browser.
// data-a, by contrast, is only read with JSON.parse: whatever is in there stays a value.
const on=(f,...a)=>`data-on="${f}" data-a="${esc(JSON.stringify(a))}"`;
const dt=t=>t?new Date(t*1000).toLocaleString(L.locale):"—";
function tabs(){document.getElementById("tabs").innerHTML=TABS.map(([k,l])=>`<div class="tab ${k==cur?'on':''}" ${on("go",k)}>${esc(l)}</div>`).join("")}
function go(k){cur=k;tabs();({users:users,sessions:sessions,devices:devices,apppw:apppw,security:security,audit:audit})[k]()}
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
        ${LINKS&&!u.is_service&&!u.disabled?`<button class=sec ${on("link",u.id,u.username)}>${esc(L["btn.link"])}</button>`:''}
        <button class=sec ${on("own",u.id,!u.is_owner)}>${esc(u.is_owner?L["btn.owner_off"]:L["btn.owner_on"])}</button>
        <button class=warn ${on("deluser",u.id)}>${esc(L["btn.delete"])}</button>
      </td></tr><tr id=r${u.id}></tr><tr id=k${u.id}></tr>`).join("")+`</table>`);
}
async function mkuser(){const b={username:nu.value,email:ne.value,password:np.value,roles:nr.value.split(",").map(s=>s.trim()).filter(Boolean),is_admin:na.checked,is_service:ns.checked};
  if(REQMAIL&&!ns.checked&&!ne.value.trim()){tsAlert(L["err.email"]);return}
  const r=await p("/api/users",b);if(!rejected(r))users()}
async function own(id,o){if(!await tsConfirm(o?L["confirm.owner_on"]:L["confirm.owner_off"]))return;rejected(await p(`/api/users/${id}/owner`,{owner:o}));users()}
async function dis(id,d){if(!await tsConfirm(d?L["confirm.disable"]:L["confirm.enable"],{danger:d}))return;rejected(await p(`/api/users/${id}/disable`,{disabled:d}));users()}
async function pw(id){const v=await tsPrompt(L["prompt.pw"],"",{type:"password"});if(v&&!rejected(await p(`/api/users/${id}/password`,{password:v})))await tsAlert(L.pw_set)}
async function ren(id,alt){const v=await tsPrompt(L["prompt.username"],alt);if(v&&v!==alt&&!rejected(await p(`/api/users/${id}/username`,{username:v})))users()}
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
// The detail row under an account shows one thing at a time: its keys, its passkeys or a sign-in link. Each view
// claims the row before it waits for the server and writes only while its claim is the newest — otherwise a reply
// that arrives late overwrites what came after it: `mkkey` refreshes the key list without waiting, and when that
// refresh landed after a sign-in link issued in the meantime, the link (shown once, never again) was gone.
const rowClaims={};
function claimRow(id){const n=(rowClaims[id]||0)+1;rowClaims[id]=n;
  return h=>{if(rowClaims[id]===n)document.getElementById("k"+id).innerHTML=h}}
async function keys(id,name){const put=claimRow(id);const ks=await g(`/api/users/${id}/keys`);
  put(`<td colspan=5><div class=card><h2>${esc(L.api_keys)} · ${esc(name)}</h2>
    <div class=row><input id=kn placeholder="${esc(L["f.key_name"])}"><input id=ke type=number placeholder="${esc(L["f.key_expires"])}" class=w150>
    <button ${on("mkkey",id)}>${esc(L.create_key)}</button></div>
    ${SVC?`<div class=row><input id=sn placeholder="${esc(L["f.service_name"])}"><select id=sr>${RESOURCES.map(r=>`<option value="${esc(r)}">${esc(r)}</option>`).join("")}</select>
    <button ${on("mksvc",id)}>${esc(L.pair_service)}</button></div>`:""}
    <table>`+ks.map(k=>`<tr><td><code>${esc(k.prefix)}</code> ${esc(k.name||'')}</td><td>${k.revoked?`<span class="badge red">${esc(L.revoked)}</span>`:`<span class="badge grn">${esc(L.active)}</span>`}</td>
      <td>${esc(L.last_used)} ${dt(k.last_used)}</td><td>${k.expires_at?esc(L.expires)+' '+dt(k.expires_at):esc(L.never_expires)}</td>
      <td>${k.revoked?'':`<button class=warn ${on("revk",k.id,id,name)}>${esc(L.revoke)}</button>`}</td></tr>`).join("")+`</table></div></td>`)}
// A pairing code (T-60) is shown ONCE — the service redeems it with `tinysesam-client pair <url> <code>`.
async function mksvc(id){const r=await p(`/api/users/${id}/service-pairing`,{name:sn.value,resources:[sr.value]});
  if(!rejected(r)&&r.code)await tsSecret(L.pairing_code,r.code,L.pairing_once+"\ntinysesam-client pair "+r.issuer+" "+r.code)}
async function mkkey(id){const r=await p(`/api/users/${id}/keys`,{name:kn.value,expires_days:ke.value?parseInt(ke.value):null});
  keys(id,"");if(!rejected(r)&&r.key)await tsSecret(L.key_new,r.key,L.key_once)}
async function pks(id,name){const put=claimRow(id);const ps=await g(`/api/users/${id}/passkeys`);
  put(`<td colspan=5><div class=card><h2>${esc(L.passkeys)} · ${esc(name)}</h2>
    <table>`+(ps.length?ps.map(c=>`<tr><td>${esc(c.name||'')}</td><td>${dt(c.created_at)}</td><td>${esc(L.last_used)} ${dt(c.last_used)}</td>
      <td><button class=warn ${on("delpk",id,c.id,name)}>${esc(L.revoke)}</button></td></tr>`).join(""):`<tr><td class=muted>${esc(L.no_passkeys)}</td></tr>`)+`</table></div></td>`)}
// Sign-in link without mail (T-33): shown ONCE — the server keeps only the hash.
async function link(id,name){const v=await tsPrompt(L["prompt.link_ttl"],String(LINKTTL),{type:"number"});if(v===null)return;
  const put=claimRow(id);const r=await p(`/api/users/${id}/signin-link`,{ttl_min:v.trim()?parseInt(v,10):null});if(rejected(r))return;
  put(`<td colspan=5><div class=card><h2>${esc(L.signin_link)} · ${esc(name)}</h2>
    <div class="muted small">${esc(L.link_once)}</div>
    <div class="row lkcopy"><input id=lk${id} readonly class=w280 value="${esc(r.url)}">
      <button class=sec ${on("copylink",id)}>${esc(L.copy)}</button><span id=lks${id} class=lkstate role=status aria-live=polite></span></div>
    ${r.qr?`<img class=qr alt="" src="${esc(r.qr)}">`:""}
    <div class="muted small">${esc(L.expires)} ${dt(r.expires_at)}</div></div></td>`)}
// T-35: copy the link once shown; without the clipboard API the field is selected for Ctrl+C.
async function copylink(id){const f=document.getElementById("lk"+id),s=document.getElementById("lks"+id);
  const ok=await tsCopy(f.value,f);s.textContent=ok?L.copied:L.copy_manual;s.className="lkstate"+(ok?"":" manual")}
async function delpk(uid,cid,name){if(await tsConfirm(L["confirm.pk_delete"],{danger:true})){rejected(await p(`/api/users/${uid}/passkeys/${cid}/delete`));pks(uid,name)}}
async function deluser(id){if(!await tsConfirm(L["confirm.delete"],{danger:true}))return;if(!rejected(await p(`/api/users/${id}/delete`)))users()}
async function revk(kid,uid,name){if(await tsConfirm(L["confirm.revoke"],{danger:true})){rejected(await p(`/api/keys/${kid}/revoke`));keys(uid,name)}}

async function sessions(){const ss=await g("/api/sessions");
  V(`<table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.method"])}</th><th>${esc(L["th.ip"])}</th><th>${esc(L["th.since"])}</th><th>${esc(L["th.mfa"])}</th><th></th></tr>`+
    ss.map(s=>`<tr><td><b>${esc(s.user)}</b></td><td>${esc(s.method)}</td><td>${esc(s.ip)}</td><td>${dt(s.created_at)}</td>
      <td>${s.mfa_ok?'✓':'—'}</td><td><button class=warn ${on("revs",s.full)}>${esc(L.end_session)}</button></td></tr>`).join("")+`</table>`)}
async function revs(t){rejected(await p("/api/sessions/revoke",{token:t}));sessions()}
async function devices(){const ds=await g("/api/oauth/devices");
  V(ds.length?`<table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.client"])}</th><th>${esc(L["th.resource"])}</th><th>${esc(L["th.since"])}</th><th>${esc(L["th.last"])}</th><th>${esc(L["th.ip"])}</th><th></th></tr>`+
    ds.map(d=>`<tr><td><b>${esc(d.username)}</b></td><td>${esc(d.client_name)} <code>${esc(d.client_id)}</code></td><td>${esc(d.resource)}</td>
      <td>${dt(d.created_at)}</td><td>${dt(d.last_used)}</td><td>${esc(d.last_ip)}</td>
      <td><button class=warn ${on("revdev",d.id)}>${esc(L.disconnect)}</button></td></tr>`).join("")+`</table>`
    :`<div class=muted>${esc(L.no_devices)}</div>`);
  if(!SVC)return;const ss=await g("/api/oauth/services");
  document.getElementById("view").insertAdjacentHTML("beforeend",`<h2>${esc(L.services)}</h2>`+(ss.length?`<table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.client"])}</th><th>${esc(L["th.resource"])}</th><th>${esc(L["th.since"])}</th><th>${esc(L["th.last"])}</th><th>${esc(L["th.ip"])}</th><th>${esc(L["th.key"])}</th><th></th></tr>`+
    ss.map(s=>`<tr><td><b>${esc(s.username)}</b></td><td>${esc(s.name)} <code>${esc(s.client_id)}</code></td><td>${esc((s.resources||[]).join(", "))}</td>
      <td>${dt(s.created_at)}</td><td>${dt(s.last_used)}</td><td>${esc(s.last_ip)||'—'}</td>
      <td>${(s.keys||[]).filter(k=>k.valid).map(k=>`<code>${esc(k.kid.slice(0,8))}</code> ${k.expires_at?esc(L.expires)+' '+dt(k.expires_at):esc(L.never_expires)}`).join("<br>")||`<span class="badge red">${esc(L.expired)}</span>`}</td>
      <td><button class=warn ${on("revsvc",s.client_id)}>${esc(L.revoke)}</button></td></tr>`).join("")+`</table>`
    :`<div class=muted>${esc(L.no_services)}</div>`))}
async function revsvc(id){if(await tsConfirm(L["confirm.revoke_service"],{danger:true})){rejected(await p(`/api/oauth/services/${encodeURIComponent(id)}/revoke`));devices()}}
async function revdev(id){if(await tsConfirm(L["confirm.disconnect"],{danger:true})){rejected(await p(`/api/oauth/devices/${id}/revoke`));devices()}}
async function apppw(){const ps=await g("/api/app-passwords");
  V(ps.length?`<table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.name"])}</th><th>${esc(L["th.apps"])}</th><th>${esc(L["th.since"])}</th><th>${esc(L["th.last"])}</th><th>${esc(L["th.ip"])}</th><th>${esc(L.expires)}</th><th></th></tr>`+
    ps.map(a=>`<tr><td><b>${esc(a.username)}</b></td><td>${esc(a.name)}</td><td>${esc((a.hosts||[]).join(", "))}</td>
      <td>${dt(a.created_at)}</td><td>${dt(a.last_used)}</td><td>${esc(a.last_ip)||'—'}</td><td>${a.expires_at?dt(a.expires_at):esc(L.never_expires)}</td>
      <td>${a.revoked?`<span class="badge red">${esc(L.revoked)}</span>`:a.expired?`<span class="badge red">${esc(L.expired)}</span>`:`<button class=warn ${on("revap",a.id)}>${esc(L.revoke)}</button>`}</td></tr>`).join("")+`</table>`
    :`<div class=muted>${esc(L.no_app_passwords)}</div>`)}
async function revap(id){if(await tsConfirm(L["confirm.revoke_app_password"],{danger:true})){rejected(await p(`/api/app-passwords/${id}/revoke`));apppw()}}
function clr(id){document.getElementById("r"+id).innerHTML=""}

async function security(){const s=await g("/api/security");const v=await g("/api/version");
  V(`<div class=card><h2>${esc(L.hardening)}</h2>`+
    Object.entries(s).map(([k,v])=>`<div class=row><label class=w230>${esc(k)}</label><input id="s_${esc(k)}" value="${esc(v)}" type=number class=w120></div>`).join("")+
    `<div class="muted small">${esc(L.hardening_owner)}</div>`+
    `<div class=row><button ${on("savesec",Object.keys(s))}>${esc(L.save)}</button></div></div>`+
    `<div class=card><h2>${esc(L.version)}</h2><div class=row>${esc(L.installed)} <code>${esc(v.version)}</code></div>
     <div class="muted small">${esc(L.update_note)}</div></div>`)}
async function savesec(keys){const b={};keys.forEach(k=>b[k]=parseInt(document.getElementById("s_"+k).value));if(!rejected(await p("/api/security",b)))await tsAlert(L.saved)}


async function audit(){const a=await g("/api/audit?limit=120");
  V(`<table><tr><th>${esc(L["th.time"])}</th><th>${esc(L["th.event"])}</th><th>${esc(L["th.user"])}</th><th>${esc(L["th.ip"])}</th><th>${esc(L["th.detail"])}</th></tr>`+
    a.map(e=>`<tr><td>${dt(e.ts)}</td><td>${esc(e.event)}</td><td>${esc(e.username)||'—'}</td><td>${esc(e.ip)||'—'}</td><td>${esc(e.detail)||''}</td></tr>`).join("")+`</table>`)}

// One delegated listener for all buttons, including those loaded later via innerHTML. Only names
// from ACT are callable — data-on selects an action, it does not name arbitrary code.
const ACT={go,mkuser,own,dis,pw,ren,roles,saveroles,clr,keys,mkkey,mksvc,revk,revs,savesec,pks,delpk,deluser,link,revdev,revsvc,revap,copylink};
document.addEventListener("click",e=>{const el=e.target.closest("[data-on]");
  if(!el||!ACT[el.dataset.on])return;ACT[el.dataset.on](...JSON.parse(el.dataset.a||"[]"))});
tabs();users();
</script>
</div>__FOOTER__</body></html>"""
