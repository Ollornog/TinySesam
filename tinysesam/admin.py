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
import time

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse

from .errors import ConfigError, RoleError, StateError
from .router import _key_kind, _mail_base, hardened_route
from . import _role_catalog, _role_levels, config_check, provisioning as _provisioning, security
from .store import name_invalid, norm_email, role_invalid, valid_email
from . import dialog as _dialog
from . import topbar as _topbar
from .templates import brand, favicon_link, inject_nonce as _inject_nonce
from .theme import TOKENS, c22_css, c22_head, theme_head


class PanelActions:
    """The rules and actions of the panel that more than one entrance uses: the panel routes and the approvals
    (`tinysesam.approvals`, stage A), which execute a confirmed action with exactly this code, as the person whose
    session confirmed it — one implementation, so the two entrances cannot drift apart. The routes decide WHO acts
    (`actor_scope`: admin, delegate or 403, CSRF, step-up); these methods decide what that actor may do to the
    target and do it."""

    def __init__(self, auth):
        self.auth = auth
        self.cfg = auth.cfg

    def fits(self, destination, me, roles) -> bool:
        """Is this account within one delegate scope (T-74)? `config_check.may_manage` decides — the same rule the
        account API applies to an application's whole-account actions."""
        if destination is None:
            return False
        return config_check.may_manage(roles, me["id"], destination, self.auth.user_roles(destination),
                                       delegate_roles=self.delegate_roles())

    def delegate_roles(self) -> frozenset:
        """The delegate roles of the running configuration (keys of `admin_delegates`)."""
        raw = getattr(self.cfg, "admin_delegates", None) or {}
        return frozenset(r for r in raw if isinstance(r, str)) if isinstance(raw, dict) else frozenset()

    def visible(self, destination, me, scopes) -> bool:
        return any(self.fits(destination, me, roles) for _, roles, _ in scopes)

    def allowed(self, scopes, action: str) -> list:
        """The scopes whose delegate role may do `action` (`can`) — 403 if none."""
        out = [s for s in scopes if action in s[2]]
        if not out:
            raise HTTPException(403, self.auth.t("api.delegate_action"))
        return out

    def target(self, me, scopes, uid: int, action: str):
        """The account a route acts on. An administrator: the owner model as before. A delegate: the action must be
        theirs (403), and the account in the scope of a delegate role that may do it — otherwise 404, the same answer
        as for an account that does not exist (no oracle)."""
        if scopes is None:
            return self.owner_protection(me, uid)
        mine = self.allowed(scopes, action)
        destination = self.auth.store.get_user(uid)
        if not self.visible(destination, me, mine):
            raise HTTPException(404, self.auth.t("api.not_found"))
        return destination

    def refused_roles(self, mine) -> HTTPException:
        return HTTPException(400, self.auth.t("api.delegate_roles",
                                              roles=", ".join(sorted({r for _, roles, _ in mine for r in roles}))))

    def delegate_roles_in(self, b: dict, scopes, action: str) -> list:
        """A delegate's `roles` from the body (create, invite): at least one, all from ONE delegate role that may do
        the action, no admin flag, no service account — checked BEFORE anything is written."""
        mine = self.allowed(scopes, action)
        if b.get("is_admin") or b.get("is_service"):
            raise HTTPException(403, self.auth.t("api.admin"))
        wanted = self.roles_from(b)
        if not wanted or not any(set(wanted) <= roles for _, roles, _ in mine):
            raise self.refused_roles(mine)
        return wanted

    def owner_protection(self, me, uid: int):
        """Only an owner may change an owner account (owner model). Otherwise an admin would set a
        new password for the owner and become owner themselves — the protection against deletion
        would then be a door with an open window next to it."""
        destination = self.auth.store.get_user(uid)
        if destination and destination["is_owner"] and not (me and me.get("is_owner")):
            raise HTTPException(403, self.auth.t("api.owner_only"))
        return destination

    def log(self, request: Request, event: str, detail=None):
        """Log an admin action — with actor and IP.

        Without both, the audit log is worthless for the post-mortem: it recorded THAT an
        account was blocked or a password reset, not by whom and from where. With
        several admins that is exactly the question asked afterwards. As with CSRF, this
        lives in one place and not in every route — the next new route inherits it.
        """
        person = self.auth.current_user(request)
        # A delegated admin (T-74) says in which role they acted — `actor=` alone would not tell an administrator
        # from a team lead afterwards.
        held = [role for role, _, _ in self.auth._delegate_scopes(person) or []] if person else []
        if held:
            detail = f"{detail} as={','.join(sorted(held))}" if detail else f"as={','.join(sorted(held))}"
        self.auth.audit(event, person["username"] if person else None, self.auth.client_ip(request), detail)

    def other_active_admins(self, uid: int) -> int:
        """How many active, interactive admins remain if `uid` stops being one?

        Counted are those who can really sign in as admin: not blocked, no
        service account (which has no session, and whose keys never carry the flag, R6-5)."""
        return sum(1 for u in self.auth.store.list_users()
                   if u["is_admin"] and not u["disabled"] and not u["is_service"]
                   and int(u["id"]) != int(uid))

    def roles_from(self, b: dict) -> list:
        """`roles` from the body: a list of strings — otherwise 400, and BEFORE any write.

        The database accepts any JSON; a role `1` or `null` was only noticed when logging
        (`','.join`), AFTER roles and admin flag had been written: HTTP 500 without an
        audit line (integration finding 8). A string like `"admin"` was silently split into
        letters by `list()`. If the field is missing (or empty), it means "no roles"."""
        raw = b.get("roles")
        if not raw:
            return []
        if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
            raise HTTPException(400, self.auth.t("api.invalid", reason="roles"))
        # A comma, a control character or surrounding spaces (T-85): Remote-Groups would carry it as another role or
        # as several — refused here, before any write, with the role named (escaped by the panel like every text).
        for role in raw:
            if role_invalid(role):
                raise HTTPException(400, self.auth.t("api.role_name", role=repr(role)))
        return list(raw)

    def set_roles(self, request: Request, me, scope, uid: int, b: dict) -> dict:
        """Set the roles (and, from the panel only, the admin flag) of an account — `POST <admin>/api/users/{id}/roles`
        and the approval type `tinysesam.account.set_roles` (which never sends `is_admin`). `me`/`scope` come from
        the caller's session: `(account, None)` for an administrator, `(account, scopes)` for a delegate."""
        destination = self.target(me, scope, uid, "roles")
        if destination is None:
            raise HTTPException(404)
        roles = self.roles_from(b)          # checked BEFORE any write, like R6-1 below
        if scope is not None:
            # A delegate (T-74) never touches the admin flag — not even to send it unchanged — and sets only roles of
            # ONE delegate role that may set roles and holds the account in its scope. The strict scope means the
            # account holds nothing outside it, so the new list replaces the old one whole.
            if "is_admin" in b:
                raise HTTPException(403, self.auth.t("api.admin"))
            mine = [s for s in self.allowed(scope, "roles") if self.fits(destination, me, s[1])]
            if not any(set(roles) <= s[1] for s in mine):
                raise self.refused_roles(mine)
            roles = list(dict.fromkeys(roles))
        if "is_admin" in b:
            new = bool(b["is_admin"])
            if not new and destination["is_owner"]:
                raise HTTPException(400, self.auth.t("api.owner_protected"))
            if new and destination["is_service"]:
                raise HTTPException(400, self.auth.t("api.service_admin"))      # R6-2, see user_create
            # Do not strip the last admin (R6-1). Without an admin the first-admin
            # path opens again: a new one-time token is created, and whoever reads it — in the log,
            # in the console — becomes admin. The panel is then unreachable for anyone
            # who could turn it back. Checked BEFORE any write, so the roles
            # are not left half set.
            if not new and destination["is_admin"] and not self.other_active_admins(uid):
                raise HTTPException(400, self.auth.t("api.last_admin"))
            # Making an account admin hands the panel to whoever holds that account — from a stale admin session
            # an account of the attacker's own (self-registered, invited) would keep the panel after the session
            # ends. New access (B-12): a fresh confirmation, also with `admin_require_mfa=False`.
            if new and not destination["is_admin"]:
                self.auth._require_fresh(request, me)
        # Before/after in the log (R6-7): "uid=5" said THAT rights changed, not
        # which. Whether someone became admin is exactly the question after an incident.
        # `str` per role: legacy data from before the check (or from own code) must not
        # blow up the line — it is written AFTER the write, and an error here meant
        # "changed, but not logged" (integration finding 8).
        before = destination
        roles_before = sorted(map(str, self.auth.user_roles(before))) if before else []
        admin_before = bool(before["is_admin"]) if before else False
        self.auth.set_roles(uid, roles)
        # Write only on a REAL change (H-5): the panel sends the tick with every
        # save of the roles. `set_admin(True)` then wrote a 1 over the 2 of a flag granted by the
        # identity provider — the revocable flag silently became a permanent
        # admin right, and the next login without the admin group no longer removed it (attack on H-5).
        if "is_admin" in b and bool(b["is_admin"]) != bool(destination["is_admin"]):
            self.auth.store.set_admin(uid, bool(b["is_admin"]))
        afterwards = self.auth.store.get_user(uid)
        roles_afterwards = sorted(map(str, self.auth.user_roles(afterwards))) if afterwards else []
        admin_afterwards = bool(afterwards["is_admin"]) if afterwards else False
        detail = (f"uid={uid} roles={','.join(roles_before) or '-'}"
                  f"->{','.join(roles_afterwards) or '-'}")
        if admin_before != admin_afterwards:
            detail += f" admin={int(admin_before)}->{int(admin_afterwards)}"
        self.log(request, "user_roles", detail)
        return {"ok": True}

    def disable(self, me, scope, uid: int, disabled: bool) -> dict:
        """Lock or unlock an account — `POST <admin>/api/users/{id}/disable` and the approval type
        `tinysesam.account.disable` (locking only)."""
        if disabled and uid == me["id"]:
            raise HTTPException(400, self.auth.t("api.no_self_lock"))
        destination = self.target(me, scope, uid, "disable")
        if disabled and destination and destination["is_owner"]:
            raise HTTPException(400, self.auth.t("api.owner_protected"))
        # The effect lives in ONE place, `auth.set_disabled` (PO decision 2026-09-27):
        # operator note (no confirmation link lifts the block, H-18), end sessions,
        # revoke keys, discard open links, audit with the admin as actor. An own
        # admin route of the app calls the same method. What depends on the caller stays here.
        if not self.auth.set_disabled(uid, disabled):
            raise HTTPException(404, self.auth.t("api.not_found"))
        return {"ok": True}

    # ---------- the account API (`apps`, `tinysesam.provisioning`) ----------
    # The application's scope is decided by `Provisioning.target` (`config_check.app_visible`, `may_manage`); these two
    # do what the application may do to an account it manages — with the panel's audit lines and the one lock effect.

    def app_set_roles(self, uid: int, allowlist, wanted) -> tuple:
        """Set the roles of an account an application manages: the roles of its `allowlist` become `wanted`, every
        other role stays — `(current − allowlist) ∪ wanted` in ONE transaction (`Store.merge_roles`), so a change
        from the panel at the same moment is not lost. Audit `user_roles` with before → after, like the panel.
        Returns `(before, after)`; 404 if the account vanished."""
        merged = self.auth.store.merge_roles(uid, list(allowlist), list(wanted))
        if merged is None:
            raise HTTPException(404, self.auth.t("api.not_found"))
        before, after = merged
        self.auth.audit("user_roles", None, None, f"uid={uid} roles={','.join(sorted(before)) or '-'}"
                                                  f"->{','.join(sorted(after)) or '-'}")
        return before, after

    def app_lock(self, uid: int, lock: bool) -> str:
        """Lock or unlock an account an application manages. Locking sets `disabled=3` only on an active account
        (`Store.lock_by_app`: a lock of the operator or of a pending confirmation is never downgraded) with the same
        effect as every lock (`auth._lock_effects`: sessions, keys, devices, app passwords, open links). Unlocking
        lifts only 3. Returns `locked`, `unlocked`, `unchanged` (nothing to do) or `operator` (unlocking refused:
        the lock is not the application's)."""
        store = self.auth.store
        u = store.get_user(uid)
        if u is None:
            raise HTTPException(404, self.auth.t("api.not_found"))
        if lock:
            if not store.lock_by_app(uid):
                return "unchanged"
            self.auth._lock_audit(u, True, self.auth._lock_effects(uid))
            return "locked"
        if store.unlock_by_app(uid):
            self.auth._lock_audit(u, False, 0)
            return "unlocked"
        now = store.get_user(uid)
        return "operator" if now is not None and now["disabled"] else "unchanged"

    # ---------- the operator and the account API: take over, release, take a deletion back (stage B) ----------

    def _app_target(self, uid: int):
        destination = self.auth.store.get_user(uid)
        if destination is None:
            raise HTTPException(404, self.auth.t("api.not_found"))
        return destination

    def adopt(self, request: Request, uid: int, app_id) -> dict:
        """Hand an account to an application (`managed_by`) — the operator's deliberate act instead of a side effect
        of roles. The one rule (`provisioning.adopt_refusal`, shared with `tinysesam accounts adopt`): no application
        manages it yet, no administrator, owner, service account or delegate, at least one role, all in the
        application's allowlist. Audit `account_adopted` under the account, the admin as `actor=`."""
        app = self.auth._provisioning().apps().get(app_id) if isinstance(app_id, str) else None
        if app is None:
            raise HTTPException(400, self.auth.t("api.invalid", reason="app"))
        destination = self._app_target(uid)
        why = _provisioning.adopt_refusal(app, destination, self.auth.user_roles(destination), self.delegate_roles())
        if why is not None or not self.auth.store.adopt_account(uid, app["id"]):
            raise HTTPException(409, self.auth.t("api.adopt_refused",
                                                 reason=self.auth.t(f"api.adopt_why.{why or 'managed'}")))
        self.auth.audit("account_adopted", str(destination["username"]), self.auth.client_ip(request),
                        f"uid={uid} app={app['id']}")
        return {"ok": True}

    def release(self, request: Request, uid: int) -> dict:
        """Take an account away from its application (`managed_by = NULL`), also from one that is no longer
        configured; a pending deletion by the application ends with it. Audit `account_released`."""
        destination = self._app_target(uid)
        app_id = destination["managed_by"]
        if not app_id or not self.auth.store.release_account(uid, app_id):
            raise HTTPException(409, self.auth.t("api.not_managed"))
        self.auth.audit("account_released", str(destination["username"]), self.auth.client_ip(request),
                        f"uid={uid} app={app_id}")
        return {"ok": True}

    def restore(self, request: Request, uid: int) -> dict:
        """Take a deletion by the application back ("cancel deletion") — also after its deadline, as long as the
        cleanup has not run. The application's lock is lifted, the operator's stays. Audit `provision_restore`."""
        destination = self._app_target(uid)
        if not destination["delete_after"] or not self.auth.store.cancel_deletion(uid):
            raise HTTPException(409, self.auth.t("api.not_deleting"))
        self.auth.audit("provision_restore", str(destination["username"]), self.auth.client_ip(request),
                        f"uid={uid} by=operator")
        return {"ok": True}

    def reset_totp(self, request: Request, me, uid: int) -> dict:
        """Reset the TOTP factor of an account (T-98) — `POST <admin>/api/users/{uid}/totp/reset` and the CLI
        `tinysesam reset-totp`: the holder lost the authenticator app and has no recovery code left. Without it the
        operator had only the whole access reset of an application (`tinysesam.account.reset_access`) or the database.

        The authenticator goes with its recovery codes (`totp_disable`: audit line under the holder and the event
        `totp_disabled`, so the holder learns of it). The failed TOTP attempts end with it — a new authenticator starts
        without a lock someone else filled. Owner model as for passkeys; a fresh confirmation, because removing a
        second factor from a stale admin session opens the account to whoever holds its password."""
        destination = self.owner_protection(me, uid)
        if destination is None:
            raise HTTPException(404, self.auth.t("api.not_found"))
        self.auth._require_fresh(request, me)
        if not self.auth.store.has_confirmed_totp(uid):
            raise HTTPException(409, self.auth.t("api.no_totp"))
        codes = self.auth.store.count_recovery_codes(uid)
        self.auth.totp_disable(uid)
        self.auth.lift_lockout(uid, methods=("totp",))
        self.log(request, "totp_reset_by_admin", f"uid={uid} recovery_codes_deleted={codes}")
        return {"ok": True, "recovery_codes_deleted": codes}

    def revoke_key(self, me, kid: int) -> dict:
        """Revoke someone's API key as administrator — `POST <admin>/api/keys/{kid}/revoke` and the approval type
        `tinysesam.apikey.revoke` for a key of another account (an own key the holder revokes without the panel)."""
        owner = self.auth.store.api_key_owner(kid)
        if owner is not None:
            self.owner_protection(me, owner)     # an owner's keys are revoked only by an owner
        # The audit line is written by `revoke_api_key` — with owner, IP and actor= (B5-04/R6-3).
        self.auth.revoke_api_key(kid)
        return {"ok": True}


#: The longest setup window the panel opens (T-130): a day. A window open for longer is the old gap under a new name.
MFA_WINDOW_MAX_MIN = 24 * 60


def build_admin_router(auth) -> APIRouter:
    cfg = auth.cfg
    ar = APIRouter(tags=["admin"], route_class=hardened_route(auth))

    def actor_scope(request: Request, delegates: bool):
        """Who acts, and how far (T-74): `(account, None)` for an administrator, `(account, scopes)` for a delegated
        admin on a route open to delegates (`auth._delegate_scopes`) — otherwise 403. The ONE place every panel route
        goes through.

        Admin + (optional) step-up MFA. Browser page request → redirect to login/reauth;
        JSON/fetch calls → 401/403 (the panel UI reloads after reauth). The scope is decided before the step-up,
        so an account without panel rights gets its 403 and not a detour through the reauth page.

        CSRF is checked HERE, not per route: two panel routes lacked the check
        (block key, delete resource) because they read no JSON body, so json_body never
        got to run. Closing a whole class is more reliable than patching it route by route
        — the next new route would be open again otherwise. The same holds for the scope: a new route is
        admin-only unless it asks for `team()` and checks its target with `target()`."""
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
        u = auth._enforce(request)
        scopes = None
        if not auth.is_admin(u):
            scopes = auth._delegate_scopes(u) if delegates else None
            if scopes is None:
                raise HTTPException(403, auth.t("api.admin"))
        if cfg.admin_require_mfa and not auth.stepup_fresh(request, u):
            if u.get("_via") == "apikey":
                raise HTTPException(403, auth.t("api.stepup_session"))
            auth._deny_stepup(request)
        return u, scopes

    def guard(request: Request):
        """Administrators only — every route that is not open to delegated admins."""
        return actor_scope(request, delegates=False)[0]

    def team(request: Request):
        """Administrators and delegated admins (T-74): `(account, None)` or `(account, scopes)`."""
        return actor_scope(request, delegates=True)

    pa = PanelActions(auth)
    fits, visible, allowed, target = pa.fits, pa.visible, pa.allowed, pa.target
    refused_roles, delegate_roles_in, owner_protection, log = (pa.refused_roles, pa.delegate_roles_in,
                                                                pa.owner_protection, pa.log)
    other_active_admins, roles_from = pa.other_active_admins, pa.roles_from

    def uview(u, apps=None, hint=False, sources=None):
        managed = u["managed_by"] or None
        app = (apps or {}).get(managed) if managed else None
        return {"id": u["id"], "username": u["username"], "display_name": u["display_name"],
                "email": u["email"], "is_admin": bool(u["is_admin"]), "is_owner": bool(u["is_owner"]),
                "is_service": bool(u["is_service"]),
                "roles": json.loads(u["roles"] or "[]"), "disabled": bool(u["disabled"]),
                # Why blocked (boundary b): 1 = confirmation of the address is pending (lifted by
                # the confirmation link), 2 = the operator (only they lift it). Previously both
                # looked the same in the panel — and anyone who took an operator block for a pending
                # confirmation waited for a link that never releases anything.
                # 3 = the application that manages the account (account API, schema 23).
                "disabled_by": {1: "confirmation", 2: "operator", 3: "app"}.get(int(u["disabled"] or 0)),
                "created_at": u["created_at"],
                # Where the account comes from (T-99, ADR-18): `local`, `oidc`, `saml`, `ldap`, two or more = mixed.
                # Shown only; no decision reads it.
                "source": (sources if sources is not None else auth.store.account_sources([u["id"]])).get(
                    int(u["id"]), ["local"]),
                # The account API (stage B): which application manages the account, whether that application is still
                # configured, and the end of a pending deletion by it.
                "managed_by": managed,
                "managed_name": _provisioning.app_name(app, managed, cfg.lang) if managed else None,
                "managed_known": app is not None, "delete_after": u["delete_after"],
                # Panel hint, administrators only (a delegate gets no application data): no configured application
                # could take this account over (`provisioning.no_app_can_adopt`, the rule of the Take-over action).
                "no_app_fits": bool(hint and _provisioning.no_app_can_adopt(apps or {}, u, auth.user_roles(u),
                                                                           pa.delegate_roles()))}

    def kview(k):
        return {"id": k["id"], "name": k["name"], "prefix": k["prefix"], "created_at": k["created_at"],
                "last_used": k["last_used"], "expires_at": k["expires_at"], "revoked": bool(k["revoked"]),
                "kind": _key_kind(k)}

    # ---------- Users / service accounts ----------
    @ar.get("/api/users")
    def users(request: Request):
        me, scopes = team(request)
        apps = auth._provisioning().apps()
        # A delegate sees only the accounts in scope — not the names and addresses of everyone else (T-74). An
        # application's account is no exception: in scope only when all its roles are (`may_manage`).
        sources = auth.store.account_sources()   # one query for the list, not one per account
        return [uview(u, apps, scopes is None, sources) for u in auth.store.list_users()
                if scopes is None or visible(u, me, scopes)]

    @ar.post("/api/users")
    async def user_create(request: Request):
        person, scope = team(request)
        b = await auth.json_body(request)
        if scope is not None:
            # A delegate (T-74): only accounts within the listed roles, never an admin or a service — and always from
            # a fresh confirmation: an account with the team's roles is a way into what those roles open.
            delegate_roles_in(b, scope, "create")
            auth._require_fresh(request, person)
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
        me, scope = team(request)
        b = await auth.json_body(request)
        return pa.disable(me, scope, uid, bool(b.get("disabled", True)))

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
        me, scope = team(request)
        b = await auth.json_body(request)
        return pa.set_roles(request, me, scope, uid, b)

    # ---------- The role catalog (schema 25): roles administrators add without a change of the configuration ----------
    # Administrators only (`guard`: CSRF, `admin_require_mfa`). No extra fresh confirmation: adding or removing a
    # catalog role gives nobody access — granting it goes through the roles route above with its rules.
    _ROLE_STATUS = {"invalid": 400, "forbidden": 403, "not_found": 404}

    def role_refused(e: RoleError) -> HTTPException:
        where = ", ".join(auth.t(f"admin.usage_{k}") for k in _role_catalog.usage_kinds(e.usage))
        text = auth.t(f"api.catalog_{e.code}", role=repr(e.role), where=where, limit=_role_catalog.LIMIT)
        return HTTPException(_ROLE_STATUS.get(e.code, 409), text)

    def role_name(b: dict, key: str = "name") -> str:
        value = b.get(key)
        if not isinstance(value, str):
            raise HTTPException(400, auth.t("api.invalid", reason=key))
        return value

    @ar.get("/api/roles")
    def roles_list(request: Request):
        guard(request)
        return _role_catalog.listing(cfg, auth.store, auth.store.roles_in_use())

    @ar.post("/api/roles")
    async def role_create(request: Request):
        me = guard(request)
        name = role_name(await auth.json_body(request))
        try:
            _role_catalog.create(cfg, auth.store, name, str(me["username"]))
        except RoleError as e:
            raise role_refused(e) from None
        log(request, "role_created", f"name={_role_catalog.detail(name)} via=panel")
        return {"ok": True, "name": name}

    @ar.post("/api/roles/delete")
    async def role_delete(request: Request):
        guard(request)
        name = role_name(await auth.json_body(request))
        try:
            res = _role_catalog.delete(cfg, auth.store, name)
        except RoleError as e:
            if e.code == "in_use":
                log(request, "role_delete_refused", f"name={_role_catalog.detail(name)} "
                                                    f"where={','.join(_role_catalog.usage_kinds(e.usage))}")
            raise role_refused(e) from None
        log(request, "role_deleted", f"name={_role_catalog.detail(name)} via=panel")
        return {"ok": True, **res}

    @ar.post("/api/roles/entry")
    async def role_entry_create(request: Request):
        me = guard(request)
        b = await auth.json_body(request)
        ladder, key = role_name(b, "ladder"), role_name(b, "key")
        try:
            res = _role_catalog.create_entry(cfg, auth.store, ladder, key, str(me["username"]))
        except RoleError as e:
            raise role_refused(e) from None
        for name in res["added"]:
            log(request, "role_created",
                f"name={_role_catalog.detail(name)} via=panel entry={_role_catalog.detail(key)}")
        return {"ok": True, **res}

    @ar.post("/api/roles/entry/delete")
    async def role_entry_delete(request: Request):
        guard(request)
        b = await auth.json_body(request)
        ladder, key = role_name(b, "ladder"), role_name(b, "key")
        try:
            res = _role_catalog.delete_entry(cfg, auth.store, ladder, key)
        except RoleError as e:
            if e.code == "in_use":
                log(request, "role_delete_refused", f"entry={_role_catalog.detail(key)} "
                                                    f"where={','.join(_role_catalog.usage_kinds(e.usage))}")
            raise role_refused(e) from None
        for name in res["removed"]:
            log(request, "role_deleted",
                f"name={_role_catalog.detail(name)} via=panel entry={_role_catalog.detail(key)}")
        return {"ok": True, **res}

    # ---------- Accounts of applications (account API, stage B): take over, release, cancel a deletion ----------
    # Administrators only. Taking over and releasing change who may lock and delete the account by key, so they ask for
    # a fresh confirmation (step-up) — also with `admin_require_mfa=False`.
    @ar.post("/api/users/{uid}/adopt")
    async def user_adopt(request: Request, uid: int):
        person = guard(request)
        owner_protection(person, uid)
        auth._require_fresh(request, person)
        b = await auth.json_body(request)
        return pa.adopt(request, uid, b.get("app"))

    @ar.post("/api/users/{uid}/release")
    def user_release(request: Request, uid: int):
        person = guard(request)
        owner_protection(person, uid)
        auth._require_fresh(request, person)
        return pa.release(request, uid)

    @ar.post("/api/users/{uid}/restore")
    def user_restore(request: Request, uid: int):
        owner_protection(guard(request), uid)
        return pa.restore(request, uid)

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

    @ar.get("/api/users/{uid}/totp")
    def user_totp(request: Request, uid: int):
        """Whether the account has a TOTP set up (T-98) — the panel offers the reset only then."""
        guard(request)
        if auth.store.get_user(uid) is None:
            raise HTTPException(404, auth.t("api.not_found"))
        window = auth.store.get_user(uid)["mfa_enroll_until"]
        return {"enabled": auth.store.has_confirmed_totp(uid),
                "recovery_left": auth.store.count_recovery_codes(uid),
                "enrollment_until": int(window) if window and int(window) > int(time.time()) else None}

    @ar.post("/api/users/{uid}/totp/reset")
    def user_totp_reset(request: Request, uid: int):
        return pa.reset_totp(request, guard(request), uid)

    # The setup window (T-130, `grant_mfa_enrollment`): with `mfa_enrollment="strict"`, or after a TOTP reset of an
    # account that is no longer new, the person may set up a second factor only while the operator holds it open.
    # Opening it lets whoever signs in next with the password bind their own authenticator — new access, so a fresh
    # confirmation; closing needs none.
    @ar.post("/api/users/{uid}/mfa-enrollment")
    async def user_mfa_enrollment(request: Request, uid: int):
        me = guard(request)
        destination = owner_protection(me, uid)
        if destination is None:
            raise HTTPException(404, auth.t("api.not_found"))
        auth._require_fresh(request, me)
        b = await auth.json_body(request)
        minutes = b.get("minutes", 60)
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= MFA_WINDOW_MAX_MIN:
            raise HTTPException(400, auth.t("api.invalid", reason=f"minutes (1–{MFA_WINDOW_MAX_MIN})"))
        until = auth.grant_mfa_enrollment(uid, minutes)
        log(request, "mfa_enrollment_granted_by_admin", f"uid={uid} minutes={minutes}")
        return {"ok": True, "until": until}

    @ar.post("/api/users/{uid}/mfa-enrollment/delete")
    def user_mfa_enrollment_delete(request: Request, uid: int):
        me = guard(request)
        if owner_protection(me, uid) is None:
            raise HTTPException(404, auth.t("api.not_found"))
        auth.revoke_mfa_enrollment(uid)
        log(request, "mfa_enrollment_revoked_by_admin", f"uid={uid}")
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
        return pa.revoke_key(guard(request), kid)

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
            person, scope = team(request)
            b = await auth.json_body(request)
            if scope is not None:
                delegate_roles_in(b, scope, "invite")       # a delegate invites like they create (T-74)
            auth._require_fresh(request, person)
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
            person, scope = team(request)
            # An owner's link is issued only by an owner; a delegate's only for an account in scope (T-74) — with it
            # the delegate can take that account over, which is the point of the link, behind step-up and audit.
            target(person, scope, uid, "signin_link")
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
        return [{"ts": a["ts"], "event": a["event"], "username": a["username"], "ip": a["ip"], "detail": a["detail"]}
                for a in auth.store.recent_audit(limit)]

    # ---------- built-in UI (optional) ----------
    if cfg.admin_ui_enabled:
        @ar.get("", response_class=HTMLResponse)
        def admin_page(request: Request):
            me, scope = team(request)
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
                                     viewer=me, csrf=auth.csrf_token(request) if cfg.csrf_enabled else "",
                                     scope=scope)
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
    "active disabled disabled_confirmation disabled_app revoked enable disable "
    "btn.pw btn.rename btn.roles btn.keys btn.passkeys btn.delete btn.owner_on btn.owner_off "
    "totp totp_on totp_off totp_reset totp_hint confirm.totp_reset totp_window totp_window_open totp_window_close "
    "passkeys no_passkeys confirm.delete confirm.pk_delete confirm.owner_on confirm.owner_off "
    "err.email err.generic confirm.disable confirm.enable confirm.revoke "
    "prompt.pw prompt.username pw_set roles_groups no_roles api_keys create_key last_used expires "
    "never_expires revoke key_once end_session hardening hardening_owner version installed update_note "
    "btn.link signin_link link_once prompt.link_ttl key_new "
    "tab.devices th.client th.resource th.last disconnect no_devices confirm.disconnect via_pairing "
    "tab.app_passwords no_app_passwords th.name th.apps expired confirm.revoke_app_password "
    "services no_services pair_service f.service_name pairing_code pairing_once th.key confirm.revoke_service "
    "delegate_note "
    "search filter_roles level_none incomplete incomplete_hint roles_other roles_unknown all_accounts "
    "sec.profile sec.access sec.signin sec.danger f.display_name created password set_password pw_hint "
    "issue_link link_hint disable_hint owner_hint delete_hint no_keys unavailable unavailable_reason "
    "source source.local source.oidc source.saml source.ldap "
    "app_badge managed_by not_configured all_apps no_app app_section adopt adopt_hint no_app_fits release release_hint "
    "confirm.release deleting deleting_until restore restore_hint "
    "roles_btn role_filter show_all roles_title roles_hint new_role role_add catalog_count src_config src_catalog "
    "src_both src_accounts accounts_n take_over delete_role why_in_use why_in_ladder role_invalid_mark entry_hint "
    "entry_key entry_add entry_delete confirm.role_delete confirm.entry_delete usage_users usage_keys usage_services "
    "usage_links usage_approvals usage_permissions"
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


def render_panel(auth, base: str, warn: str = "", prefix: str = "", viewer=None, csrf: str = "",
                 scope=None) -> str:
    """Panel HTML for a given API base. The only place where `_PAGE` is filled —
    so that e.g. a demo/preview embedding shows the same UI as the real panel.

    `viewer` (the signed-in admin) and `csrf` feed the top bar's account menu (T-64); without a viewer the bar
    shows logo and name only. `scope`: the scopes of a delegated admin (T-74, `auth._delegate_scopes`) — the page
    then shows only their roles and actions. Only a view: the routes enforce every limit themselves.

    The language comes from `cfg.lang`, as with every other built-in page. Whoever switches it per
    request (`?lang=`) gets the panel delivered translated.
    """
    cfg = auth.cfg
    view = None if scope is None else {"roles": sorted({r for _, roles, _ in scope for r in roles}),
                                       "can": sorted({a for _, _, can in scope for a in can})}
    # The role levels over the roles THIS viewer may grant: a delegate is offered a level only when every role of it
    # lies in their scope (`_role_levels.entries`) — a view, the roles route checks the scope itself.
    # An administrator is offered `available_roles` ∪ the role catalog (`auth.known_roles`), a delegate their scope.
    offered = auth.known_roles() if view is None else view["roles"]
    ladders = _role_levels.view(getattr(cfg, "role_levels", None) or [], offered, cfg.lang)
    seen = dict(viewer) if viewer else {}
    me = {"id": seen.get("id"), "owner": bool(seen.get("is_owner"))}
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
            .replace("__ROLES__", json.dumps(list(offered))
                     .replace("<", "\\u003c"))
            .replace("__SCOPE__", "null" if view is None else json.dumps(view).replace("<", "\\u003c"))
            .replace("__LADDERS__", json.dumps(ladders, ensure_ascii=False).replace("<", "\\u003c"))
            .replace("__APPS__", json.dumps([] if view is not None else [
                {"id": a, "name": _provisioning.app_name(e, a, cfg.lang)}
                for a, e in sorted(auth._provisioning().apps().items())], ensure_ascii=False).replace("<", "\\u003c"))
            .replace("__ME__", json.dumps(me).replace("<", "\\u003c"))
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
.tsadmin .badge.app{background:var(--ts-chip);color:var(--ts-ink);border:1px solid var(--ts-line)}
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
.tsadmin [hidden]{display:none!important}
/* Accounts: a slim list, one detail page per account (no button bar per row). */
.tsadmin .bar{justify-content:space-between}
.tsadmin .grow{flex:1;min-width:180px}
.tsadmin tr.click{cursor:pointer}
.tsadmin tr.click:hover td{background:var(--ts-surface)}
.tsadmin td.roles{white-space:normal}
.tsadmin .chip{display:inline-block;padding:1px 8px;margin:1px 0;border-radius:20px;font-size:11px;
  background:var(--ts-chip);color:var(--ts-ink);border:1px solid var(--ts-line-soft)}
.tsadmin .chip.warn{background:var(--ts-warn-bg);color:var(--ts-warn-ink);border-color:var(--ts-warn-line)}
.tsadmin .chip.more{color:var(--ts-muted)}
.tsadmin .back{display:inline-block;margin:0 0 8px;font-size:13px}
.tsadmin .dhead{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 14px}
.tsadmin h2.uname{font-size:20px;text-transform:none;letter-spacing:0;color:var(--ts-ink);margin:0 6px 0 0}
.tsadmin dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:8px 18px;margin:0;font-size:13px;align-items:center}
.tsadmin dl.kv dt{color:var(--ts-muted)}
.tsadmin dl.kv dd{margin:0;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.tsadmin .line{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0;
  border-top:1px solid var(--ts-line-soft);flex-wrap:wrap}
.tsadmin .line:first-of-type{border-top:0;padding-top:0}
.tsadmin .line .what{flex:1;min-width:200px;font-size:13px}
.tsadmin .line .what .muted{font-size:12px;margin-top:2px}
.tsadmin .sub{margin-top:8px;width:100%}
.tsadmin .card.danger{border-color:var(--ts-danger)}
.tsadmin .card.danger h2{color:var(--ts-err-ink)}
/* The role picker: per ladder a grid of entries, each a row of level segments (radios); other roles as a grid of
   checkboxes per prefix. The chosen segment carries a check mark, not only a colour. */
.tsadmin .picker fieldset{border:1px solid var(--ts-line-soft);border-radius:8px;margin:0 0 10px;padding:6px 10px 10px}
.tsadmin .picker legend{font-size:12px;font-weight:600;color:var(--ts-muted);padding:0 4px}
.tsadmin .picker .pfilter{margin:0 0 10px;width:100%;max-width:320px}
.tsadmin .ents{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:6px 22px;align-items:start}
.tsadmin .ent{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:3px 0}
.tsadmin .ent .key{font-weight:600;font-size:13px;overflow-wrap:anywhere;min-width:70px}
.tsadmin .ent .warnline,.tsadmin .ent .whyline{flex-basis:100%}
.tsadmin .segs{display:inline-flex;border:1px solid var(--ts-field-line);border-radius:7px;overflow:hidden}
.tsadmin .seg{position:relative;display:block}
.tsadmin .seg input{position:absolute;opacity:0;width:1px;height:1px;margin:0}
.tsadmin .seg span{display:block;padding:4px 10px;font-size:12px;cursor:pointer;background:var(--ts-field-bg);
  color:var(--ts-ink);border-left:1px solid var(--ts-field-line);min-width:44px;text-align:center}
.tsadmin .seg:first-child span{border-left:0}
.tsadmin .seg input:checked+span{background:var(--ts-accent);color:var(--ts-accent-ink);font-weight:600}
/* "—" chosen is no access: neutral, the accent colour stays for a real level. */
.tsadmin .seg input[value="-1"]:checked+span{background:var(--ts-neutral);color:var(--ts-neutral-ink)}
.tsadmin .seg span::before{content:"✓ ";visibility:hidden}
.tsadmin .seg input:checked+span::before{visibility:visible}
.tsadmin .seg input:focus-visible+span{outline:2px solid var(--ts-link);outline-offset:-2px}
.tsadmin .seg input:disabled+span{cursor:not-allowed;color:var(--ts-muted);text-decoration:line-through;
  background:var(--ts-surface-2)}
.tsadmin label{font-size:13px}
.tsadmin .warnline{font-weight:400;color:var(--ts-warn-ink);margin-top:2px}
.tsadmin .chks{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:4px 14px}
.tsadmin .chks label{display:flex;gap:6px;align-items:center;font-size:13px;overflow-wrap:anywhere;padding:2px 0}
.tsadmin .form{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px 12px;margin-bottom:12px}
@media (max-width:640px){
  .tsadmin .wrap{padding:14px 12px}
  .tsadmin table.ulist thead{display:none}
  .tsadmin table.ulist tr{display:grid;grid-template-columns:1fr auto;gap:4px 10px;padding:10px 2px;
    border-bottom:1px solid var(--ts-line-soft)}
  .tsadmin table.ulist td{border:0;padding:0;white-space:normal}
  .tsadmin table.ulist td.type{text-align:right}
  .tsadmin table.ulist td.roles{grid-column:1/-1}
  .tsadmin dl.kv{grid-template-columns:1fr;gap:2px}
  .tsadmin dl.kv dd{margin-bottom:8px}
}
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
const ROLES=__ROLES__;                                 // known roles (available_roles ∪ role catalog; a delegate: their list)
const SCOPE=__SCOPE__;                                 // null = administrator; {roles,can} = delegated admin (T-74) — a view only, the server decides
const LADDERS=__LADDERS__;                             // config.role_levels over the roles this viewer may grant: [{label,levels,entries:[{key,own,offer}]}]
const APPS=__APPS__;                                   // applications with the account API: [{id,name}] (administrators only; [] for a delegate)
const ME=__ME__;                                       // the viewer: {id, owner} — hides what the server would refuse anyway
const CAN=a=>!SCOPE||SCOPE.can.includes(a);            // may the viewer do this action (`can` of their delegate roles)?
const REQMAIL=__REQMAIL__;                             // config.signup_require_email (e-mail required)
const L=__I18N__;                                      // texts in config.lang — see messages.py
const LINKS=__LINKS__;                                 // config.magiclink_enabled: admin may issue sign-in links
const LINKTTL=__LINKTTL__;                             // config.magiclink_ttl_min: default validity of a link
const OAUTH=__OAUTH__;                                 // config.oauth_enabled: tab "connected programs" (T-36)
const APPPW=__APPPW__;                                 // an application takes app passwords: tab "app passwords" (T-66)
const SVC=__SVC__;                                     // config.oauth_service_clients: pair services (T-60)
const RESOURCES=__RESOURCES__;                         // config.oauth_resources: what a service may be paired for
const TABS=SCOPE?[["users",L["tab.users"]]]:[["users",L["tab.users"]],["sessions",L["tab.sessions"]]].concat(OAUTH?[["devices",L["tab.devices"]]]:[]).concat(APPPW?[["apppw",L["tab.app_passwords"]]]:[]).concat([["security",L["tab.security"]],["audit",L["tab.audit"]]]);
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
function go(k){cur=k;tabs();if(location.hash)history.replaceState(null,"",location.pathname+location.search);({users:users,sessions:sessions,devices:devices,apppw:apppw,security:security,audit:audit})[k]()}
const V=h=>document.getElementById("view").innerHTML=h;

// ---------- Accounts: a slim list, a detail page per account (`#user/<id>`), a form for a new one (`#new`) ----------
let US=[];                                             // the account list as last loaded
let RF="";                                             // the role filter of the list (`#role/<name>`), "" = none
// The roles a ladder covers (every role an entry's levels add) — the rest of ROLES is grouped by prefix.
const COVERED=new Set(LADDERS.flatMap(l=>l.entries.flatMap(e=>e.own)));
const OTHERS=ROLES.filter(r=>!COVERED.has(r));
// The level an account holds in one ladder entry: the highest level whose role it holds, and whether it holds exactly
// the roles up to that level. An incomplete entry (`coll:a` without `coll:a-read`) preselects no level: saving keeps
// those roles as they are until the admin picks one — the picker never widens rights on its own.
function stateOf(e,held){const f=e.own.map(r=>held.has(r)),top=f.lastIndexOf(true);
  return {level:top,complete:f.every((x,i)=>x===(i<=top))}}
const badges=u=>`${u.is_owner?'<span class="badge grn">owner</span> ':''}${u.is_admin?'<span class="badge grn">admin</span> ':''}${u.is_service?'<span class="badge svc">service</span>':'<span class=badge>user</span>'}${u.managed_by?` <span class="badge app">${esc(L.app_badge.replace("{name}",u.managed_name||u.managed_by))}</span>`:''}`;
// The account API (stage B): an account being deleted by its application says so, with the date it goes for good.
const state=u=>u.delete_after?`<span class="badge red">${esc(L.deleting_until.replace("{date}",dt(u.delete_after)))}</span>`:u.disabled?`<span class="badge red">${esc(u.disabled_by==="confirmation"?L.disabled_confirmation:u.disabled_by==="app"?L.disabled_app:L.disabled)}</span>`:`<span class="badge grn">${esc(L.active)}</span>`;
// Roles as chips: one per ladder entry ("a · write"), an incomplete one marked in words, then the other roles.
function chips(u,max){const held=new Set(u.roles||[]),out=[];
  for(const l of LADDERS)for(const e of l.entries){const s=stateOf(e,held);if(s.level<0)continue;
    out.push(s.complete?`<span class=chip>${esc(e.key)} · ${esc(l.levels[s.level])}</span>`
      :`<span class="chip warn">⚠ ${esc(e.key)} · ${esc(L.incomplete)}</span>`);e.own.forEach(r=>held.delete(r))}
  held.forEach(r=>out.push(`<span class=chip>${esc(r)}</span>`));
  if(!out.length)return '<span class=muted>—</span>';
  return out.slice(0,max||99).join(" ")+(max&&out.length>max?` <span class="chip more">+${out.length-max}</span>`:"")}
async function users(){US=await g("/api/users");route()}
async function refresh(){US=await g("/api/users");route()}
function nav(h){if(location.hash===h)route();else location.hash=h}
// What the users tab shows follows the address: back/forward and a bookmarked account work.
function route(){if(cur!=="users")return;const m=location.hash.match(/^#user\/(\d+)$/);
  const u=m&&US.find(x=>x.id===+m[1]);if(u)return detail(u);
  if(location.hash==="#new"&&CAN("create"))return newform();
  if(location.hash==="#roles"&&!SCOPE)return rolesview();
  const rm=location.hash.match(/^#role\/(.+)$/);RF=rm?decodeURIComponent(rm[1]):"";
  list()}
function list(){
  V(`${SCOPE?`<div class="muted small">${esc(L.delegate_note)} ${esc(SCOPE.roles.join(", "))}</div>`:""}
    <div class="row bar"><input id=us type=search class=grow data-filter=rows aria-label="${esc(L.search)}" placeholder="${esc(L.search)}">
    ${appfilter()}${SCOPE?"":`<button class=sec ${on("nav","#roles")}>${esc(L.roles_btn)}</button>`}${CAN("create")?`<button ${on("nav","#new")}>${esc(L.new_user)}</button>`:""}</div>
    ${RF?`<div class="row rfilter"><span class=chip>${esc(L.role_filter.replace("{role}",RF))}</span><a href="#" ${on("nav","")}>${esc(L.show_all)}</a></div>`:""}
    <table class=ulist><thead><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.type"])}</th><th>${esc(L["th.roles"])}</th><th>${esc(L["th.status"])}</th></tr></thead><tbody>`+
    US.map(u=>`<tr class=click data-app="${esc(u.managed_by||"")}" data-roles="${esc(JSON.stringify(u.roles||[]))}" data-q="${esc([u.username,u.email,u.display_name,...(u.roles||[])].join(" ").toLowerCase())}" ${on("nav","#user/"+u.id)}>
      <td><a href="#user/${u.id}"><b>${esc(u.username)}</b></a>${u.email?`<div class="muted small">${esc(u.email)}</div>`:""}</td>
      <td class=type>${badges(u)}</td><td class=roles>${chips(u,6)}</td><td>${state(u)}</td></tr>`).join("")+`</tbody></table>`);
  FILTER.rows()}
// The role picker: per ladder a table with one row per entry and a radio per level; the other roles as checkboxes
// grouped by prefix (`xyz:`); roles the account holds that nobody configured stay ticked under their own heading, so
// saving never drops them unseen. Without known roles: the free-text field as before. `pid` names the container.
function picker(pid,roles){const held=new Set(roles||[]);
  if(!ROLES.length&&!SCOPE)return `<input id="${pid}" value="${esc((roles||[]).join(", "))}" placeholder="${esc(L["f.roles"])}" class=w280>`;
  let n=0,h="";
  // A delegate sees only the levels they may grant (all roles in their scope) and no entry without one; an
  // administrator sees a level whose roles are not configured struck through, with the reason in words.
  LADDERS.forEach((l,li)=>{let rows="";
    l.entries.forEach((e,ei)=>{if(SCOPE&&!e.offer.some(Boolean))return;
      n++;const s=stateOf(e,held),nm=`${pid}_${li}_${ei}`,why=[];
      const seg=(i,text,title,off)=>`<label class=seg title="${esc(title)}"><input type=radio name="${nm}" value=${i} aria-label="${esc(e.key+": "+text+(off?" — "+off:""))}"${off?" disabled":""}${s.complete&&s.level===i?" checked":""}><span>${esc(i<0?"—":text)}</span></label>`;
      const segs=e.own.map((r,i)=>{if(e.offer[i])return seg(i,l.levels[i],e.own.slice(0,i+1).join(", "),"");
        if(SCOPE)return "";
        const off=L.unavailable+": "+L.unavailable_reason.replace("{roles}",e.own.slice(0,i+1).filter(x=>!ROLES.includes(x)).join(", "));
        why.push(l.levels[i]+" — "+off);return seg(i,l.levels[i],off,off)}).join("");
      rows+=`<div class=ent data-q="${esc(e.key.toLowerCase())}"><span class=key>${esc(e.key)}</span><span class=segs role=radiogroup aria-label="${esc(e.key)}">`+
        seg(-1,L.level_none,L.level_none,"")+segs+`</span>`+
        why.map(w=>`<div class="muted small whyline">${esc(w)}</div>`).join("")+
        (s.complete?"":`<div class="warnline small">⚠ ${esc(L.incomplete)}: ${esc(e.own.filter(r=>held.has(r)).join(", "))} — ${esc(L.incomplete_hint)}</div>`)+`</div>`});
    if(rows)h+=`<fieldset><legend>${esc(l.label)}</legend><div class=ents>${rows}</div></fieldset>`});
  const groups={};OTHERS.forEach(r=>{const i=r.indexOf(":"),k=i>0?r.slice(0,i+1):"";(groups[k]=groups[k]||[]).push(r)});
  const unknown=[...held].filter(r=>!COVERED.has(r)&&!OTHERS.includes(r));
  const box=(title,rs)=>`<fieldset><legend>${esc(title)}</legend><div class=chks>`+rs.map(r=>{n++;
    return `<label data-q="${esc(r.toLowerCase())}"><input type=checkbox value="${esc(r)}"${held.has(r)?" checked":""}> ${esc(r)}</label>`}).join("")+`</div></fieldset>`;
  Object.keys(groups).sort((a,b)=>(a==="")-(b==="")||a.localeCompare(b)).forEach(k=>{h+=box(k||L.roles_other,groups[k])});
  if(unknown.length)h+=box(L.roles_unknown,unknown);
  return `<div class=picker id="${pid}">${n>12?`<input type=search class=pfilter data-filter=roles data-p="${pid}" aria-label="${esc(L.filter_roles)}" placeholder="${esc(L.filter_roles)}">`:""}${h||`<span class=muted>${esc(L.no_roles)}</span>`}</div>`}
// The roles the picker stands for: per entry the roles up to the chosen level (none for "—"), an entry left without a
// choice (only an incomplete one) keeps the roles it held, plus every ticked checkbox. Hidden by the filter ≠ removed.
function collect(pid,roles){const held=new Set(roles||[]),box=document.getElementById(pid);
  if(!box||box.tagName==="INPUT")return ((box&&box.value)||"").split(",").map(s=>s.trim()).filter(Boolean);
  const out=[];
  LADDERS.forEach((l,li)=>l.entries.forEach((e,ei)=>{const c=box.querySelector(`input[name="${pid}_${li}_${ei}"]:checked`);
    if(!c){e.own.forEach(r=>{if(held.has(r))out.push(r)});return}
    out.push(...e.own.slice(0,parseInt(c.value,10)+1))}));
  box.querySelectorAll("input[type=checkbox]:checked").forEach(c=>out.push(c.value));
  return [...new Set(out)]}
// The filter by application (stage B): the configured ones and every other value an account carries (an application
// that is no longer configured), plus "no application". Only when there is anything to choose.
function appfilter(){const ids=[...new Set(APPS.map(a=>a.id).concat(US.map(u=>u.managed_by).filter(Boolean)))];
  if(!ids.length)return "";
  const name=id=>{const a=APPS.find(x=>x.id===id),u=US.find(x=>x.managed_by===id);return a?a.name:((u&&u.managed_name)||id)+" ("+L.not_configured+")"};
  return `<select id=uf data-filter=rows aria-label="${esc(L.all_apps)}"><option value="*">${esc(L.all_apps)}</option>`+
    ids.map(id=>`<option value="${esc(id)}">${esc(L.app_badge.replace("{name}",name(id)))}</option>`).join("")+
    `<option value="">${esc(L.no_app)}</option></select>`}
const FILTER={
  rows:()=>{const q=((document.getElementById("us")||{}).value||"").trim().toLowerCase(),f=document.getElementById("uf"),a=f?f.value:"*";
    // The role filter (`#role/<name>`, from the roles page): exactly that role, not every role containing the text.
    document.querySelectorAll("table.ulist tbody tr").forEach(t=>{t.hidden=(!!q&&!t.dataset.q.includes(q))||(a!=="*"&&t.dataset.app!==a)
      ||(!!RF&&!JSON.parse(t.dataset.roles||"[]").includes(RF))})},
  roles:f=>{const q=f.value.trim().toLowerCase(),box=document.getElementById(f.dataset.p);
    box.querySelectorAll("[data-q]").forEach(t=>{t.hidden=!!q&&!t.dataset.q.includes(q)});
    box.querySelectorAll("fieldset").forEach(s=>{s.hidden=!s.querySelector("[data-q]:not([hidden])")})}};
document.addEventListener("input",e=>{const f=e.target.closest&&e.target.closest("[data-filter]");if(f&&FILTER[f.dataset.filter])FILTER[f.dataset.filter](f)});
document.addEventListener("change",e=>{const f=e.target.closest&&e.target.closest("select[data-filter]");if(f&&FILTER[f.dataset.filter])FILTER[f.dataset.filter](f)});
const line=(what,hint,act,sub)=>`<div class=line><div class=what><b>${esc(what)}</b>${hint?`<div class=muted>${esc(hint)}</div>`:""}</div>${act||""}${sub||""}</div>`;
function detail(u){const admin=!SCOPE,svc=u.is_service,self=u.id===ME.id;
  const signin=[
    admin&&!svc?line(L.password,L.pw_hint,`<button class=sec ${on("pw",u.id)}>${esc(L.set_password)}</button>`):"",
    admin&&!svc?line(L.passkeys,"","",`<div id=pkl class=sub></div>`):"",
    admin&&!svc?line(L.totp,L.totp_hint,"",`<div id=tol class=sub></div>`):"",
    admin?line(L.api_keys,"","",`<div id=kl class=sub></div>`):"",
    LINKS&&CAN("signin_link")&&!svc&&!u.disabled?line(L.signin_link,L.link_hint,`<button class=sec ${on("link",u.id,u.username)}>${esc(L.issue_link)}</button>`,`<div id=lko class=sub></div>`):""].join("");
  const danger=[
    CAN("disable")&&!self&&!(u.is_owner&&!u.disabled)?line(u.disabled?L.enable:L.disable,u.disabled?"":L.disable_hint,`<button class="${u.disabled?'ok':'warn'}" ${on("dis",u.id,!u.disabled)}>${esc(u.disabled?L.enable:L.disable)}</button>`):"",
    admin&&ME.owner?line(u.is_owner?L["btn.owner_off"]:L["btn.owner_on"],L.owner_hint,`<button class=sec ${on("own",u.id,!u.is_owner)}>${esc(u.is_owner?L["btn.owner_off"]:L["btn.owner_on"])}</button>`):"",
    admin&&!self&&!u.is_owner?line(L["btn.delete"],L.delete_hint,`<button class=warn ${on("deluser",u.id)}>${esc(L["btn.delete"])}</button>`):""].join("");
  // The account API (stage B), administrators only: cancel a deletion by the application, release the account, or take
  // it over for an application (the server applies the rule and asks for a step-up).
  const appl=admin&&!svc?[
    u.no_app_fits?`<div class="line noappfits" role=note><div class=what><div class=muted>${esc(L.no_app_fits)}</div></div></div>`:"",
    u.delete_after?line(L.deleting_until.replace("{date}",dt(u.delete_after)),L.restore_hint,`<button class=ok ${on("restore",u.id)}>${esc(L.restore)}</button>`):"",
    u.managed_by?line(L.release,L.release_hint,`<button class=sec ${on("release",u.id)}>${esc(L.release)}</button>`):"",
    !u.managed_by&&APPS.length&&!u.is_admin&&!u.is_owner?line(L.adopt,L.adopt_hint,`<span class=row><select id=ua aria-label="${esc(L.adopt)}">${APPS.map(a=>`<option value="${esc(a.id)}">${esc(a.name)}</option>`).join("")}</select><button class=sec ${on("adopt",u.id)}>${esc(L.adopt)}</button></span>`):""].join(""):"";
  V(`<a href="#" class=back ${on("nav","")}>← ${esc(L.all_accounts)}</a>
    <div class=dhead><h2 class=uname>${esc(u.username)}</h2>${badges(u)} ${state(u)}</div>
    <section class=card><h2>${esc(L["sec.profile"])}</h2><dl class=kv>
      <dt>${esc(L["f.username"])}</dt><dd><b>${esc(u.username)}</b>${admin?`<button class=sec ${on("ren",u.id,u.username)}>${esc(L["btn.rename"])}</button>`:""}</dd>
      <dt>${esc(L["f.display_name"])}</dt><dd>${esc(u.display_name)||'<span class=muted>—</span>'}</dd>
      <dt>${esc(L["f.email"])}</dt><dd>${esc(u.email)||'<span class=muted>—</span>'}</dd>
      <dt>${esc(L.created)}</dt><dd>${dt(u.created_at)}</dd>
      <dt>${esc(L.source)}</dt><dd class=source>${(u.source||[]).map(s=>`<span class=badge>${esc(L["source."+s]||s)}</span>`).join(" ")}</dd>
      ${u.managed_by?`<dt>${esc(L.managed_by)}</dt><dd class=managed><span class="badge app">${esc(u.managed_name||u.managed_by)}</span>${u.managed_known?"":` <span class=muted>(${esc(L.not_configured)})</span>`}</dd>`:""}</dl></section>
    <section class=card><h2>${esc(L["sec.access"])}</h2>${CAN("roles")?picker("pk",u.roles)+`
      <div class=row>${admin&&!svc?`<label class=mr12><input type=checkbox id=ra${u.is_admin?" checked":""}> ${esc(L["f.admin"])}</label>`:""}
      <button ${on("saveroles",u.id)}>${esc(L.save)}</button><span id=rs class="muted small" role=status aria-live=polite></span></div>`:chips(u)}</section>
    ${signin?`<section class=card><h2>${esc(L["sec.signin"])}</h2>${signin}</section>`:""}
    ${appl?`<section class="card appcard"><h2>${esc(L.app_section)}</h2>${appl}</section>`:""}
    ${danger?`<section class="card danger"><h2>${esc(L["sec.danger"])}</h2>${danger}</section>`:""}`);
  if(admin){keys(u.id);if(!svc){pks(u.id);totp(u)}}}
// ---------- Roles (`#roles`, administrators only): the role catalog — roles added here are offered like those of the
// configuration. Adding grants nothing; only an unused catalog role can be deleted (the server checks again). After a
// change the page reloads, so the role picker and the role levels know the new list.
async function rolesview(){const R=await g("/api/roles"),by={};R.roles.forEach(r=>by[r.name]=r);
  const used=u=>Object.keys(u).filter(k=>u[k]).map(k=>L["usage_"+k]+": "+u[k]).join(", ");
  const why=r=>r.reason==="in_use"?L.why_in_use.replace("{where}",used(r.usage)):r.reason==="in_ladder"?L.why_in_ladder:"";
  const act=r=>{if(r.invalid)return `<span class="badge red">⚠ ${esc(L.role_invalid_mark)}</span>`;
    if(r.source==="accounts")return `<button class=sec ${on("mkrole",r.name)}>${esc(L.take_over)}</button>`;
    if(r.source==="config")return "";
    return r.deletable?`<button class=warn ${on("delrole",r.name)}>${esc(L.delete_role)}</button>`:`<span class="muted small">${esc(why(r))}</span>`};
  const n=r=>r.usage.users?`<a href="#role/${encodeURIComponent(r.name)}">${esc(L.accounts_n.replace("{n}",r.usage.users))}</a>`:esc(L.accounts_n.replace("{n}",0));
  const rows=R.roles.map(r=>line(r.name,L["src_"+r.source],`<span class="small">${n(r)}</span> ${act(r)}`)).join("");
  const cat=R.roles.filter(r=>r.source==="catalog"||r.source==="both").length;
  // Role levels: a new entry adds every level role at once; an entry whose roles are all unused catalog roles goes as
  // a whole (a single level would leave half an entry).
  const lad=R.ladders.map(l=>{const sh=LADDERS.find(x=>x.name===l.name),ents=sh?sh.entries:[];
    const ent=e=>{const rs=e.own.map(x=>by[x]).filter(Boolean),gone=rs.length===e.own.length&&rs.every(r=>r.source==="catalog"&&!Object.values(r.usage).some(Boolean));
      return line(e.key,e.own.join(", "),gone?`<button class=warn ${on("delentry",l.name,e.key,e.own)}>${esc(L.entry_delete)}</button>`:"")};
    return `<section class=card><h2>${esc(l.label)}</h2><div class="muted small">${esc(L.entry_hint.replace("{roles}",l.templates.join(", ")))}</div>
      <div class="row"><input id="ek_${esc(l.name)}" class=grow aria-label="${esc(L.entry_key)}" placeholder="${esc(L.entry_key)}">
      <button ${on("mkentry",l.name)}>${esc(L.entry_add)}</button></div>${ents.map(ent).join("")}</section>`}).join("");
  V(`<a href="#" class=back ${on("nav","")}>← ${esc(L.all_accounts)}</a>
    <section class="card rolecard"><h2>${esc(L.roles_title)}</h2><div class="muted small">${esc(L.roles_hint)}</div>
    <div class="row"><input id=nr class=grow maxlength=64 aria-label="${esc(L.new_role)}" placeholder="${esc(L.new_role)}">
    <button ${on("mkrole")}>${esc(L.role_add)}</button></div>
    <div class="muted small">${esc(L.catalog_count.replace("{n}",cat).replace("{limit}",R.limit))}</div>
    ${rows||`<span class=muted>${esc(L.no_roles)}</span>`}</section>${lad}`)}
const reloadRoles=()=>{location.hash="#roles";location.reload()};
async function mkrole(name){const v=name||((document.getElementById("nr")||{}).value||"");
  if(!v.trim())return;if(!rejected(await p("/api/roles",{name:v})))reloadRoles()}
async function delrole(name){if(!await tsConfirm(L["confirm.role_delete"].replace("{role}",name),{danger:true}))return;
  if(!rejected(await p("/api/roles/delete",{name})))reloadRoles()}
async function mkentry(ladder){const v=(document.getElementById("ek_"+ladder)||{}).value||"";
  if(!v.trim())return;if(!rejected(await p("/api/roles/entry",{ladder,key:v})))reloadRoles()}
async function delentry(ladder,key,roles){if(!await tsConfirm(L["confirm.entry_delete"].replace("{key}",key).replace("{roles}",roles.join(", ")),{danger:true}))return;
  if(!rejected(await p("/api/roles/entry/delete",{ladder,key})))reloadRoles()}
function newform(){
  V(`<a href="#" class=back ${on("nav","")}>← ${esc(L.all_accounts)}</a>
    <section class=card><h2>${esc(L.new_user)}</h2><div class=form>
    <input id=nu aria-label="${esc(L["f.username"])}" placeholder="${esc(L["f.username"])}"><input id=ne type=email aria-label="${esc(L["f.email"])}" placeholder="${esc(REQMAIL?L["f.email"]:L["f.email_optional"])}">
    <input id=nd aria-label="${esc(L["f.display_name"])}" placeholder="${esc(L["f.display_name"])}"><input id=np type=password autocomplete=new-password aria-label="${esc(L["f.password"])}" placeholder="${esc(L["f.password"])}"></div>
    ${SCOPE?"":`<div class=row><label class=mr12><input type=checkbox id=na> ${esc(L["f.admin"])}</label><label><input type=checkbox id=ns> ${esc(L["f.service"])}</label></div>`}
    <h2>${esc(L["sec.access"])}</h2>${picker("pkn",[])}
    <div class=row><button ${on("mkuser")}>${esc(L.create)}</button></div></section>`)}
async function mkuser(){const b={username:nu.value,email:ne.value,password:np.value,display_name:nd.value||null,roles:collect("pkn",[])};
  // A delegate's form has no admin/service box (T-74); the fields stay out of the body altogether.
  if(!SCOPE){b.is_admin=na.checked;b.is_service=ns.checked}
  if(REQMAIL&&!b.is_service&&!ne.value.trim()){tsAlert(L["err.email"]);return}
  const r=await p("/api/users",b);if(!rejected(r)){US=await g("/api/users");nav("#user/"+r.id)}}
async function own(id,o){if(!await tsConfirm(o?L["confirm.owner_on"]:L["confirm.owner_off"]))return;rejected(await p(`/api/users/${id}/owner`,{owner:o}));refresh()}
async function dis(id,d){if(!await tsConfirm(d?L["confirm.disable"]:L["confirm.enable"],{danger:d}))return;rejected(await p(`/api/users/${id}/disable`,{disabled:d}));refresh()}
async function pw(id){const v=await tsPrompt(L["prompt.pw"],"",{type:"password"});if(v&&!rejected(await p(`/api/users/${id}/password`,{password:v})))await tsAlert(L.pw_set)}
async function ren(id,alt){const v=await tsPrompt(L["prompt.username"],alt);if(v&&v!==alt&&!rejected(await p(`/api/users/${id}/username`,{username:v})))refresh()}
async function saveroles(id){const u=US.find(x=>x.id===id)||{roles:[]};
  const b={roles:collect("pk",u.roles)};const ra=document.getElementById("ra");
  if(!SCOPE&&ra)b.is_admin=!!ra.checked;   // a delegate never sends the flag (T-74)
  if(!rejected(await p(`/api/users/${id}/roles`,b))){await refresh();const s=document.getElementById("rs");if(s)s.textContent=L.saved}}
// Each part of the detail page (keys, passkeys, sign-in link) claims its box before it waits for the server and
// writes only while its claim is the newest — otherwise a late reply overwrites what came after it: `mkkey` refreshes
// the key list without waiting, and a link shown once must not be replaced by a list that arrived late.
const claims={};
function claim(box){const n=(claims[box]||0)+1;claims[box]=n;
  return h=>{const el=document.getElementById(box);if(claims[box]===n&&el)el.innerHTML=h}}
async function keys(id){const put=claim("kl");const ks=await g(`/api/users/${id}/keys`);
  put(`<div class=row><input id=kn placeholder="${esc(L["f.key_name"])}"><input id=ke type=number placeholder="${esc(L["f.key_expires"])}" class=w200>
    <button class=sec ${on("mkkey",id)}>${esc(L.create_key)}</button></div>
    ${SVC?`<div class=row><input id=sn placeholder="${esc(L["f.service_name"])}"><select id=sr>${RESOURCES.map(r=>`<option value="${esc(r)}">${esc(r)}</option>`).join("")}</select>
    <button class=sec ${on("mksvc",id)}>${esc(L.pair_service)}</button></div>`:""}
    ${ks.length?`<table>`+ks.map(k=>`<tr><td><code>${esc(k.prefix)}</code> ${esc(k.name||'')}</td><td>${k.revoked?`<span class="badge red">${esc(L.revoked)}</span>`:`<span class="badge grn">${esc(L.active)}</span>`}</td>
      <td>${esc(L.last_used)} ${dt(k.last_used)}</td><td>${k.expires_at?esc(L.expires)+' '+dt(k.expires_at):esc(L.never_expires)}</td>
      <td>${k.revoked?'':`<button class=warn ${on("revk",k.id,id)}>${esc(L.revoke)}</button>`}</td></tr>`).join("")+`</table>`:`<div class="muted small">${esc(L.no_keys)}</div>`}`)}
// A pairing code (T-60) is shown ONCE — the service redeems it with `tinysesam-client pair <url> <code>`.
async function mksvc(id){const r=await p(`/api/users/${id}/service-pairing`,{name:sn.value,resources:[sr.value]});
  if(!rejected(r)&&r.code)await tsSecret(L.pairing_code,r.code,L.pairing_once+"\ntinysesam-client pair "+r.issuer+" "+r.code)}
async function mkkey(id){const r=await p(`/api/users/${id}/keys`,{name:kn.value,expires_days:ke.value?parseInt(ke.value):null});
  keys(id);if(!rejected(r)&&r.key)await tsSecret(L.key_new,r.key,L.key_once)}
async function pks(id){const put=claim("pkl");const ps=await g(`/api/users/${id}/passkeys`);
  put(ps.length?`<table>`+ps.map(c=>`<tr><td>${esc(c.name||'')}</td><td>${dt(c.created_at)}</td><td>${esc(L.last_used)} ${dt(c.last_used)}</td>
      <td><button class=warn ${on("delpk",id,c.id)}>${esc(L.revoke)}</button></td></tr>`).join("")+`</table>`:`<div class="muted small">${esc(L.no_passkeys)}</div>`)}
// TOTP (T-98): state and, for an account that has one, the reset — an owner account only by an owner (the server
// checks again and asks for a step-up).
async function totp(u){const put=claim("tol");const t=await g(`/api/users/${u.id}/totp`);
  const mine=!u.is_owner||ME.owner;
  // Not set up: the setup window (T-130) — open for an hour, or closed again while it runs.
  const win=t.enrollment_until?`<span class=muted>${esc(L.totp_window_open.replace("{date}",dt(t.enrollment_until)))}</span>${mine?`<button class=sec ${on("totpwin",u.id,false)}>${esc(L.totp_window_close)}</button>`:""}`
    :(mine?`<button class=sec ${on("totpwin",u.id,true)}>${esc(L.totp_window)}</button>`:"");
  put(t.enabled?`<div class=row><span class="badge grn">${esc(L.totp_on)}</span>${mine?`<button class=warn ${on("totpreset",u.id)}>${esc(L.totp_reset)}</button>`:""}</div>`
    :`<div class=row><span class="muted small">${esc(L.totp_off)}</span>${win}</div>`)}
async function totpwin(id,open){
  if(!rejected(await p(`/api/users/${id}/mfa-enrollment${open?"":"/delete"}`,open?{minutes:60}:{})))totp(US.find(x=>x.id===id)||{id})}
async function totpreset(id){if(!await tsConfirm(L["confirm.totp_reset"],{danger:true}))return;
  if(!rejected(await p(`/api/users/${id}/totp/reset`)))totp(US.find(x=>x.id===id)||{id})}
// Sign-in link without mail (T-33): shown ONCE — the server keeps only the hash.
async function link(id,name){const v=await tsPrompt(L["prompt.link_ttl"],String(LINKTTL),{type:"number"});if(v===null)return;
  const put=claim("lko");const r=await p(`/api/users/${id}/signin-link`,{ttl_min:v.trim()?parseInt(v,10):null});if(rejected(r))return;
  put(`<div class="muted small">${esc(L.link_once)}</div>
    <div class="row lkcopy"><input id=lk${id} readonly class=w280 value="${esc(r.url)}">
      <button class=sec ${on("copylink",id)}>${esc(L.copy)}</button><span id=lks${id} class=lkstate role=status aria-live=polite></span></div>
    ${r.qr?`<img class=qr alt="" src="${esc(r.qr)}">`:""}
    <div class="muted small">${esc(L.expires)} ${dt(r.expires_at)}</div>`)}
// T-35: copy the link once shown; without the clipboard API the field is selected for Ctrl+C.
async function copylink(id){const f=document.getElementById("lk"+id),s=document.getElementById("lks"+id);
  const ok=await tsCopy(f.value,f);s.textContent=ok?L.copied:L.copy_manual;s.className="lkstate"+(ok?"":" manual")}
async function delpk(uid,cid){if(await tsConfirm(L["confirm.pk_delete"],{danger:true})){rejected(await p(`/api/users/${uid}/passkeys/${cid}/delete`));pks(uid)}}
async function adopt(id){const s=document.getElementById("ua");if(!s)return;if(!rejected(await p(`/api/users/${id}/adopt`,{app:s.value})))refresh()}
async function release(id){if(!await tsConfirm(L["confirm.release"]))return;if(!rejected(await p(`/api/users/${id}/release`)))refresh()}
async function restore(id){if(!rejected(await p(`/api/users/${id}/restore`)))refresh()}
async function deluser(id){if(!await tsConfirm(L["confirm.delete"],{danger:true}))return;if(!rejected(await p(`/api/users/${id}/delete`))){US=await g("/api/users");nav("")}}
async function revk(kid,uid){if(await tsConfirm(L["confirm.revoke"],{danger:true})){rejected(await p(`/api/keys/${kid}/revoke`));keys(uid)}}

async function sessions(){const ss=await g("/api/sessions");
  V(`<table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.method"])}</th><th>${esc(L["th.ip"])}</th><th>${esc(L["th.since"])}</th><th>${esc(L["th.mfa"])}</th><th></th></tr>`+
    ss.map(s=>`<tr><td><b>${esc(s.user)}</b></td><td>${esc(s.method)}</td><td>${esc(s.ip)}</td><td>${dt(s.created_at)}</td>
      <td>${s.mfa_ok?'✓':'—'}</td><td><button class=warn ${on("revs",s.full)}>${esc(L.end_session)}</button></td></tr>`).join("")+`</table>`)}
async function revs(t){rejected(await p("/api/sessions/revoke",{token:t}));sessions()}
async function devices(){const ds=await g("/api/oauth/devices");
  V(ds.length?`<table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.client"])}</th><th>${esc(L["th.resource"])}</th><th>${esc(L["th.since"])}</th><th>${esc(L["th.last"])}</th><th>${esc(L["th.ip"])}</th><th></th></tr>`+
    ds.map(d=>`<tr><td><b>${esc(d.username)}</b></td><td>${esc(d.client_name)} <code>${esc(d.client_id)}</code>${d.via==="pairing"?`<br><small class=muted>${esc(L.via_pairing)}</small>`:""}</td><td>${esc(d.resource)}</td>
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
const ACT={go,nav,mkuser,own,dis,pw,ren,saveroles,keys,mkkey,mksvc,revk,revs,savesec,pks,delpk,totpreset,totpwin,deluser,link,revdev,revsvc,revap,adopt,release,restore,mkrole,delrole,mkentry,delentry,copylink};
document.addEventListener("click",e=>{const el=e.target.closest("[data-on]");
  if(!el||!ACT[el.dataset.on])return;ACT[el.dataset.on](...JSON.parse(el.dataset.a||"[]"))});
// Back/forward to an account or the new-account form also from another tab.
window.addEventListener("hashchange",()=>{if(cur==="users")return route();
  if(/^#(user\/\d+|new|roles|role\/.+)$/.test(location.hash)){cur="users";tabs();users()}});
tabs();users();
</script>
</div>__FOOTER__</body></html>"""
