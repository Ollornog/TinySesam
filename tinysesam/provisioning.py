"""The account API for applications, stages A and B: an application manages the accounts it creates itself.

    TinySesamConfig(available_roles=["example-member", "example-editor"], magiclink_enabled=True,
                    base_url="https://auth.example.com",
                    apps={"example": {"account": "svc-example", "name": "Example",
                                      "provisioning": {"roles": ["example-member", "example-editor"],
                                                       "scopes": ["users:read", "users:invite",
                                                                  "users:update", "users:disable",
                                                                  "users:delete"]}}})

The application calls TinySesam directly (not through the proxy) with an automation key of its service account:

    POST  /auth/api/users                       create (users:invite) → a one-time link until the first sign-in
    GET   /auth/api/users, /auth/api/users/{id}  read (users:read)
    PATCH /auth/api/users/{id}                  display name and the roles of its allowlist (users:update)
    POST  /auth/api/users/{id}/disable|enable   lock with its own mark `disabled=3`, lift only that (users:disable)
    POST  /auth/api/users/{id}/signin-link      a new one-time link, only before the first sign-in (users:invite)
    DELETE /auth/api/users/{id}                 never signed in: for good (204); otherwise locked, gone after
                                                `delete_grace_days` (202, users:delete)
    POST  /auth/api/users/{id}/restore          take a deletion back within the grace period (users:delete)
    GET   /auth/api/provisioning                what the application may do (no scope)

Create and `signin-link` take an optional `next` (T-94): where the link leads once the first sign-in and its setup are
complete — else `provisioning.welcome_url`, else the usual target. A path or an address on the host of `base_url` or in
`trusted_redirect_hosts` (`config_check.link_next_ok`); anything else is 400 `next_invalid` before anything is written.
The target is stored with the token, never in the link.

The operator takes accounts over for an application (`managed_by`) or releases them — panel and
`tinysesam accounts adopt|release|restore|list`; `adopt_refusal` is the one rule both apply.

Resetting the access of an account that has signed in before is no route here: it is the approval type
`tinysesam.account.reset_access` (`POST /auth/api/approvals`, scope `users:reset`), which a person holding
`provisioning.approver_role` confirms with a step-up — see `tinysesam.approvals`.

Narrow on purpose (draft "account API", PO 2026-11-22): ownership only by `users.managed_by`; an account the application
did not create, an administrator, an owner, a service account and a delegate answer 404 like an account that does not
exist — decided before any field is read; roles only from the allowlist (never `admin` or a delegate role, rule E4);
no password, passkey, TOTP or address after creation; the link never after the first sign-in (that would be a takeover)
and never in the audit or a log. A write names the person the application acts for (`TinySesam-On-Behalf-Of`); the
audit keeps that as `actor_claimed=`, beside `actor=`, the service account — the claim is not proof.

The checks of the panel stay where they are: the roles and the lock go through `admin.PanelActions` (`app_set_roles`,
`app_lock`), the whole-account rule is `config_check.may_manage`, shared with the delegates of the panel (T-74).
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response

from . import config_check, security
from .errors import ConfigError, StateError
from .store import name_invalid, norm_email, norm_identifier, valid_email

#: The header with the account the application claims to act for (a decimal id, or `-` for a job without a person).
ACTOR_HEADER = "tinysesam-on-behalf-of"
#: The longest display name, like a username (`TinySesam.NAME_MAX`).
DISPLAY_MAX = 150
#: List page size: default and maximum.
PAGE_DEFAULT, PAGE_MAX = 100, 200
#: Fields of the bodies (anything else → 400 `invalid`: a typo must not pass silently).
CREATE_FIELDS = ("username", "display_name", "email", "roles", "next")
#: Fields of the body of `POST …/{id}/signin-link` (the body is optional).
LINK_FIELDS = ("next",)
UPDATE_FIELDS = ("display_name", "roles")
STATES = ("active", "disabled", "disabled_operator", "deleting")
_ID = re.compile(r"^[1-9][0-9]{0,17}$")
_MAX_ROLES = 50


class ProvisioningError(Exception):
    """A refused request: `code` is the machine word in the JSON answer, `status` the HTTP status."""

    def __init__(self, code: str, status: int, detail: str = "", retry_after: int = 0, **extra):
        super().__init__(code)
        self.code, self.status, self.detail, self.retry_after, self.extra = code, status, detail, retry_after, extra


def _now() -> int:
    return int(time.time())


def _role_ok(r) -> bool:
    return (isinstance(r, str) and 0 < len(r) <= 100 and "," not in r and r == r.strip()
            and not any(ord(z) < 32 or ord(z) == 127 for z in r))


def _int(value, default: int, low: int, high: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else default


def normalize_apps(cfg) -> dict:
    """The applications of `cfg.apps` that may use the account API, normalized — `{app_id: settings}`.

    Fail-closed for a configuration changed at runtime (construction already refused a broken one, see
    `config_check._apps`): an entry with a bad id, without a service account or without a `provisioning` block is
    left out; a role that is `admin`, a delegate role, a role of a group map, unlisted or malformed is dropped from the
    allowlist; an unknown scope counts for nothing; a number out of range falls back to its default; an
    `approver_role` that is malformed, unlisted, `admin` or grantable by any application is None, and `users:reset`
    counts for nothing without one; a `welcome_url` outside the redirect circle (`config_check.link_next_ok`) is
    None."""
    raw = getattr(cfg, "apps", None) or {}
    if not isinstance(raw, dict):
        return {}
    delegates = getattr(cfg, "admin_delegates", None) or {}
    delegates = set(delegates) if isinstance(delegates, dict) else set()
    mapped = set(config_check._mapped_roles(cfg))
    known = set(getattr(cfg, "available_roles", None) or [])
    max_ttl = _int(getattr(cfg, "signin_link_max_ttl_min", 0), 24 * 60, 1, 10 ** 6)
    # Every role ANY application may grant: never an approver role (straw-account attack, `config_check`).
    grantable = {r for e in raw.values() if isinstance(e, dict) and isinstance(e.get("provisioning"), dict)
                 and isinstance(e["provisioning"].get("roles"), list) for r in e["provisioning"]["roles"]
                 if isinstance(r, str)}
    out: dict = {}
    for app_id, entry in raw.items():
        if not isinstance(app_id, str) or not config_check.APP_ID.match(app_id) or not isinstance(entry, dict):
            continue
        account, block = entry.get("account"), entry.get("provisioning")
        if not isinstance(account, str) or not account.strip() or not isinstance(block, dict):
            continue
        raw_roles, raw_scopes, raw_limits = block.get("roles"), block.get("scopes"), block.get("limits")
        roles: list = raw_roles if isinstance(raw_roles, list) else []
        allow = [r for r in dict.fromkeys(roles) if _role_ok(r) and r != "admin" and r not in delegates
                 and r not in mapped and r in known]
        scopes: list = raw_scopes if isinstance(raw_scopes, list) else []
        limits: dict = raw_limits if isinstance(raw_limits, dict) else {}
        name = entry.get("name")
        approver = block.get("approver_role")
        if not (_role_ok(approver) and approver != "admin" and approver in known and approver not in grantable):
            approver = None
        granted = [s for s in config_check.PROVISIONING_SCOPES if s in scopes
                   and (s != "users:reset" or approver is not None)]
        out[app_id] = {
            "id": app_id, "account": account, "name": name if isinstance(name, (str, dict)) else None,
            "roles": allow, "scopes": granted, "approver_role": approver,
            # T-94: where the application's links lead after the first sign-in when a request names no `next`.
            "welcome_url": block.get("welcome_url") if config_check.link_next_ok(cfg, block.get("welcome_url"))
            else None,
            "link_ttl_min": min(_int(block.get("link_ttl_min"), config_check.PROVISIONING_DEFAULTS["link_ttl_min"],
                                     1, max_ttl), max_ttl),
            "max_accounts": _int(block.get("max_accounts"), config_check.PROVISIONING_DEFAULTS["max_accounts"],
                                 1, config_check.PROVISIONING_MAX_ACCOUNTS),
            "delete_grace_days": _int(block.get("delete_grace_days"),
                                      config_check.PROVISIONING_DEFAULTS["delete_grace_days"],
                                      0, config_check.PROVISIONING_GRACE_MAX),
            "limits": {k: _int(limits.get(k), v, 1, config_check.PROVISIONING_LIMIT_MAX)
                       for k, v in config_check.PROVISIONING_LIMITS.items()},
        }
    return out


def app_name(app: Optional[dict], app_id: str, lang: str = "en") -> str:
    """How the panel and the CLI name an application: its `name` in `lang` (a text, or a mapping language → text,
    falling back to English and then to any entry), else its id."""
    name = (app or {}).get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    if isinstance(name, dict):
        for k in (lang, "en"):
            if isinstance(name.get(k), str) and name[k].strip():
                return name[k].strip()
        for v in name.values():
            if isinstance(v, str) and v.strip():
                return v.strip()
    return app_id


def adopt_refusal(app: dict, target, target_roles, delegate_roles=frozenset()) -> Optional[str]:
    """Why the operator may NOT take `target` over for `app` (`managed_by = app id`) — None when it may.

    The one rule of the panel action and `tinysesam accounts adopt`: an account no application manages yet, no
    administrator, owner, service account or delegate, at least one role, and every role in the application's
    allowlist (`config_check.may_manage`, strict like a delegate scope). "Holds one allowlist role" is not enough: the
    application could then lock or delete an account that also carries the part of another application or the
    operator. Returns `not_found`, `managed`, `admin`, `owner`, `service`, `delegate`, `no_roles` or `foreign_roles`.
    Pure."""
    if target is None:
        return "not_found"
    if target["managed_by"]:
        return "managed"
    for word in ("is_admin", "is_owner", "is_service"):
        if target[word]:
            return word[3:]
    roles = [r for r in target_roles or []]
    if any(isinstance(r, str) and r in delegate_roles for r in roles):
        return "delegate"
    if not roles:
        return "no_roles"
    if not config_check.may_manage(frozenset(app["roles"]), None, target, roles, delegate_roles=delegate_roles):
        return "foreign_roles"
    return None


def no_app_can_adopt(apps: dict, target, target_roles, delegate_roles=frozenset()) -> bool:
    """Should the panel warn that NO configured application could take `target` over? True when applications with the
    account API exist, the account is unmanaged, no administrator, owner or service account (those are no candidates
    anyway), and `adopt_refusal` refuses it for every one of them — the same rule as the panel action and
    `tinysesam accounts adopt`, so hint and behaviour cannot drift apart. A hint only, never a block. Pure."""
    if not apps or target is None or target["managed_by"]:
        return False
    if any(target[w] for w in ("is_admin", "is_owner", "is_service")):
        return False
    return all(adopt_refusal(a, target, target_roles, delegate_roles) is not None for a in apps.values())


def deletion_due(row, now: Optional[int] = None) -> bool:
    """Has the grace period of a deletion by an application run out? Then the account is gone for the application
    (404) even before the cleanup removes it."""
    after = row["delete_after"] if row is not None else None
    if not after:
        return False
    return int(after) <= int(_now() if now is None else now)


class Provisioning:
    """The account API of one TinySesam instance (`auth._provisioning()`)."""

    def __init__(self, auth):
        self.auth = auth
        self.cfg = auth.cfg
        self.store = auth.store

    # ---------- configuration ----------
    def apps(self) -> dict:
        """`normalize_apps` of the running configuration — computed again when it changes at runtime."""
        try:
            key = json.dumps([getattr(self.cfg, "apps", None), getattr(self.cfg, "admin_delegates", None),
                              getattr(self.cfg, "available_roles", None)], sort_keys=True, default=repr)
        except (TypeError, ValueError):
            return {}
        cached = getattr(self, "_cache", None)
        if cached is None or cached[0] != key:
            cached = (key, normalize_apps(self.cfg))
            self._cache = cached
        return cached[1]

    def _delegate_roles(self) -> frozenset:
        raw = getattr(self.cfg, "admin_delegates", None) or {}
        return frozenset(r for r in raw if isinstance(r, str)) if isinstance(raw, dict) else frozenset()

    def _panel(self):
        return self.auth._panel_actions()

    # ---------- the caller ----------
    def caller(self, request: Request) -> dict:
        """The application whose service account holds the API key of this request — the only credential the account
        API takes. Resolved through `verify_api_key` alone, never `current_user()` (there a session wins over the
        key): a session cookie is no caller, and beside a key it changes nothing. Demanded: an automation key, an
        account with `is_service == 1` (exactly, like `Remote-Kind: service`), and that account named as `account`
        of an application with `provisioning`. The call goes to TinySesam directly, not through the proxy — so the
        kind of account is checked here, no header is trusted."""
        auth = self.auth
        key = auth._extract_api_key(request) if getattr(self.cfg, "apikey_enabled", False) else None
        if not key:
            raise ProvisioningError("unauthenticated", 401, "an automation key of the application's service account")
        auth._remember_request(request)
        u, _scope = auth.verify_api_key(key)
        if u is None:
            raise ProvisioningError("unauthenticated", 401, "an automation key of the application's service account")
        # The kind from the key itself (`api_key_kind`), not from `_last_key_kind`: that attribute belongs to the
        # instance and another thread may have overwritten it in between.
        kind = auth.api_key_kind(key)
        auth._remember_request(request, u)
        app = None
        if kind == "automation" and u.get("is_service") == 1:
            name = str(u.get("username") or "").lower()
            app = next((a for a in self.apps().values() if a["account"].lower() == name), None)
        if app is None:
            auth.audit("provision_denied", u["username"], None, f"reason=not_a_provisioning_app kind={_safe(kind)}")
            raise ProvisioningError("not_a_provisioning_app", 403,
                                    "the key does not belong to the service account of an application")
        return app

    def need(self, app: dict, scope: str) -> None:
        if scope not in app["scopes"]:
            self.auth.audit("provision_denied", None, None, f"app={app['id']} reason=scope scope={scope}")
            raise ProvisioningError("scope_missing", 403, scope)

    def claim(self, request: Request, app: dict, write: bool) -> None:
        """Record the application and the person it claims to act for in every audit line of this request. Required
        for a write (`400 actor_required`); it must be an active account that is no service account (`400
        actor_invalid`) — whether that person may do the action, the application decides, not TinySesam. Answers
        `actor_invalid` count against `taken_per_hour`: they would otherwise tell which ids are active persons."""
        raw = (request.headers.get(ACTOR_HEADER) or "").strip()
        claimed = f"app={app['id']}"
        if raw == "-":
            claimed += " actor_claimed=-"
        elif raw:
            person = self.store.get_user(int(raw)) if _ID.match(raw) else None
            if person is None or person["disabled"] or person["is_service"]:
                self._spend_oracle(app)
                raise ProvisioningError("actor_invalid", 400, "TinySesam-On-Behalf-Of: an active person's id or -")
            claimed += f" actor_claimed={_safe(person['username'])}#{int(person['id'])}"
        elif write:
            raise ProvisioningError("actor_required", 400, "TinySesam-On-Behalf-Of: an account id or - for a job")
        self.auth._claim_for_audit(claimed)

    # ---------- limits (per application and hour or day, in the shared `flow` table) ----------
    @staticmethod
    def _window(day: bool = False) -> tuple[int, int]:
        now = _now()
        span = 86400 if day else 3600
        return now // span, span - now % span

    def _key(self, app: dict, action: str, day: bool = False) -> str:
        return f"prov:{app['id']}:{action}:{'day:' if day else ''}{self._window(day)[0]}"

    def spend(self, app: dict, action: str) -> None:
        """Count one use of `action` (`create`, `disable`, `link`, `taken`, `delete`) — 429 `limit` beyond its hourly
        limit (and its daily one, `delete_per_day`), with a security-log warning and the audit line
        `provision_throttled`. The counters live in the database, so several workers on one file share them."""
        for day in (False, True):
            name = f"{action}_per_{'day' if day else 'hour'}"
            if name not in app["limits"]:
                continue
            if not self.store.count_up(self._key(app, action, day), app["limits"][name], 86500 if day else 3700):
                self._throttled(app, action, day)

    def _throttled(self, app: dict, action: str, day: bool = False):
        self.auth.audit("provision_throttled", None, None,
                        f"app={app['id']} action={action} window={'day' if day else 'hour'}")
        security.seclog.warning("account API throttled app=%s action=%s window=%s ip=%s", security.for_log(app["id"]),
                                action, "day" if day else "hour", security.for_log((self._ip() or "-")))
        raise ProvisioningError("limit", 429, f"{action}_per_{'day' if day else 'hour'}",
                                retry_after=self._window(day)[1])

    def _ip(self) -> Optional[str]:
        return self.auth._request_ip()

    def _oracle_spent(self, app: dict) -> bool:
        return self.store.counter(self._key(app, "taken")) >= app["limits"]["taken_per_hour"]

    def _spend_oracle(self, app: dict) -> None:
        self.spend(app, "taken")

    # ---------- the target ----------
    def target(self, app: dict, uid: Any, whole: bool = False):
        """The account row a route acts on — 404 `not_found` for one that does not exist, one the application did not
        create, an administrator, owner, service account or delegate (`config_check.app_visible`): the same answer
        everywhere, BEFORE any field of the request is read (a 400 would otherwise tell that the account exists).
        `whole=True` (display name, lock, link): additionally all roles in the allowlist (`config_check.may_manage`),
        otherwise 409 `account_shared` — the application sees the account, so that is no oracle, and the action would
        act on the part another application or the operator gave it."""
        text = str(uid)
        row = self.store.get_user(int(text)) if _ID.match(text) else None
        delegates = self._delegate_roles()
        roles = self.auth.user_roles(row) if row is not None else []
        # A deletion whose grace period has run out is final for the application, before the cleanup gets to it.
        if not config_check.app_visible(app["id"], row, roles, delegates) or deletion_due(row):
            self.auth.audit("provision_denied", None, None, f"app={app['id']} reason=not_found uid={_safe(text)[:20]}")
            raise ProvisioningError("not_found", 404)
        if whole and not config_check.may_manage(frozenset(app["roles"]), None, row, roles,
                                                 delegate_roles=delegates, without_roles=True):
            raise ProvisioningError("account_shared", 409, "the account holds roles outside the application's allowlist")
        return row

    @staticmethod
    def not_deleting(row) -> None:
        """A write on an account in its grace period (other than restoring or deleting it again) → 409: unlocking it
        would leave an active account the cleanup deletes, a new role or link would outlive the deletion."""
        if row["delete_after"]:
            raise ProvisioningError("account_deleting", 409, "the account is being deleted; restore it first")

    @staticmethod
    def state(row) -> str:
        if row["delete_after"]:
            return "deleting"
        d = int(row["disabled"] or 0)
        if d == 0:
            return "active"
        return "disabled" if d == 3 else "disabled_operator"

    def view(self, app: dict, row) -> dict:
        """What the application reads of one of its accounts: the roles only as the intersection with its allowlist
        (another role is not its business, `other_roles` says that one exists)."""
        roles = [str(r) for r in self.auth.user_roles(row)]
        allow = set(app["roles"])
        return {"id": int(row["id"]), "username": row["username"], "display_name": row["display_name"],
                "email": row["email"], "email_verified": bool(row["email_verified"]),
                "roles": sorted(r for r in roles if r in allow), "other_roles": any(r not in allow for r in roles),
                "state": self.state(row), "created_at": row["created_at"], "first_login_at": row["first_login_at"],
                "last_login_at": row["last_login_at"], "delete_after": row["delete_after"],
                "source": self.auth.store.account_sources([row["id"]]).get(int(row["id"]), ["local"])}

    # ---------- body checks ----------
    def _roles(self, app: dict, value, at_least_one: bool) -> list:
        if not isinstance(value, list) or len(value) > _MAX_ROLES or not all(isinstance(r, str) for r in value):
            raise ProvisioningError("invalid", 400, "roles")
        wanted = list(dict.fromkeys(value))
        outside = [r for r in wanted if r not in app["roles"]]
        if outside or (at_least_one and not wanted):
            self.auth.audit("provision_denied", None, None, f"app={app['id']} reason=role")
            raise ProvisioningError("role_not_allowed", 400, "roles must come from the allowlist"
                                    + ("" if wanted else ", at least one"), roles=list(app["roles"]))
        return wanted

    @staticmethod
    def _display(value) -> str:
        if not isinstance(value, str):
            raise ProvisioningError("invalid", 400, "display_name")
        text = value.strip()
        if not text or len(text) > DISPLAY_MAX or name_invalid(text):
            raise ProvisioningError("invalid", 400, "display_name: 1 to 150 characters, no control characters")
        return text

    @staticmethod
    def _fields(body, allowed: tuple) -> dict:
        if not isinstance(body, dict):
            raise ProvisioningError("invalid", 400, "a JSON object")
        unknown = sorted(set(body) - set(allowed))
        if unknown:
            raise ProvisioningError("invalid", 400, f"field {unknown[0]} is not accepted")
        return body

    # ---------- actions ----------
    def info(self, request: Request) -> dict:
        app = self.caller(request)
        remaining = {}
        for k, v in app["limits"].items():
            action, unit = k.rsplit("_per_", 1)
            remaining[k] = max(0, v - self.store.counter(self._key(app, action, unit == "day")))
        return {"app": app["id"], "name": app["name"], "scopes": app["scopes"], "roles": app["roles"],
                "approver_role": app["approver_role"],
                "link_ttl_min": app["link_ttl_min"], "max_accounts": app["max_accounts"],
                "delete_grace_days": app["delete_grace_days"],
                "accounts": self.store.count_managed(app["id"]), "limits": dict(app["limits"]),
                "remaining": remaining}

    def read(self, request: Request, uid) -> dict:
        app = self.caller(request)
        self.need(app, "users:read")
        self.claim(request, app, write=False)
        return self.view(app, self.target(app, uid))

    def listing(self, request: Request, params) -> dict:
        app = self.caller(request)
        self.need(app, "users:read")
        self.claim(request, app, write=False)
        unknown = sorted(set(params) - {"limit", "after", "role", "state"})
        if unknown:
            raise ProvisioningError("invalid", 400, f"parameter {unknown[0]} is not accepted")
        limit_text, after_text = params.get("limit", str(PAGE_DEFAULT)), params.get("after", "0")
        if not re.fullmatch(r"[0-9]{1,4}", limit_text) or not 1 <= int(limit_text) <= PAGE_MAX:
            raise ProvisioningError("invalid", 400, f"limit: 1 to {PAGE_MAX}")
        if not re.fullmatch(r"[0-9]{1,18}", after_text):
            raise ProvisioningError("invalid", 400, "after: an account id")
        role, state = params.get("role"), params.get("state")
        if state is not None and state not in STATES:
            raise ProvisioningError("invalid", 400, "state: " + ", ".join(STATES))
        limit, after = int(limit_text), int(after_text)
        delegates = self._delegate_roles()
        users: list = []
        nxt = None
        while nxt is None:
            rows = self.store.list_managed(app["id"], after, 500)
            if not rows:
                break
            for row in rows:
                after = int(row["id"])
                roles = self.auth.user_roles(row)
                if not config_check.app_visible(app["id"], row, roles, delegates) or deletion_due(row):
                    continue
                v = self.view(app, row)
                if (role is not None and role not in v["roles"]) or (state is not None and v["state"] != state):
                    continue
                if len(users) == limit:
                    nxt = users[-1]["id"]
                    break
                users.append(v)
            if len(rows) < 500:
                break
        return {"users": users, "next": nxt}

    def create(self, request: Request, app: dict, body: Any) -> dict:
        """`POST /auth/api/users` — `app` is the caller (`caller`), resolved before the body was read."""
        auth, cfg = self.auth, self.cfg
        self.need(app, "users:invite")
        self.claim(request, app, write=True)
        b = self._fields(body, CREATE_FIELDS)
        target = self._link_next(app, b.get("next"))       # before anything is written: a bad target is the caller's
        roles = self._roles(app, b.get("roles"), at_least_one=True)
        email = None
        if b.get("email") not in (None, ""):
            if not isinstance(b["email"], str) or not valid_email(norm_email(b["email"]) or ""):
                raise ProvisioningError("email_invalid", 400, "email")
            email = norm_email(b["email"])
        username = b.get("username")
        if username is not None and not isinstance(username, str):
            raise ProvisioningError("invalid", 400, "username")
        username = (username or "").strip()
        if cfg.login_identifier == "email":
            # The name follows the address in this mode.
            if not email:
                raise ProvisioningError("invalid", 400, "email: required, the username follows the address")
            if username and norm_email(username) != email:
                raise ProvisioningError("invalid", 400, "username: follows the address in this mode")
            username = email
        if not username:
            raise ProvisioningError("invalid", 400, "username")
        if len(username) > auth.NAME_MAX or name_invalid(username) or (
                cfg.login_identifier != "email" and "@" in norm_identifier(username)):
            raise ProvisioningError("name_invalid", 400, "username")
        display = self._display(b["display_name"]) if b.get("display_name") not in (None, "") else username
        if self._oracle_spent(app):
            self._throttled(app, "taken")
        if self.store.count_managed(app["id"]) >= app["max_accounts"]:
            raise ProvisioningError("quota_reached", 409, f"max_accounts={app['max_accounts']}")
        # A name or address from `admin_identifiers` answers like a taken one: such an account would become
        # administrator at its first sign-in, and the allowlist stays hidden.
        allow = {norm_identifier(i) for i in (cfg.admin_identifiers or []) if str(i).strip()}
        for field, value in (("username", username), ("email", email)):
            if value and (auth.identifier_taken(value) or norm_identifier(value) in allow
                          or (field == "email" and auth._allowlist_address(value))):
                raise self._taken(app, field)
        self.spend(app, "create")
        try:
            uid = auth._create_account(username, roles=roles, display_name=display, email=email,
                                       email_verified=False, managed_by=app["id"])
        except ConfigError as e:
            raise self._taken(app, "email" if getattr(e, "field", None) == "email" else "username") from None
        auth.audit("user_create", None, None, f"{username} service=False uid={uid}")
        try:
            link = auth._signin_link(uid, ttl_min=app["link_ttl_min"], app_id=app["id"], next=target)
        except (ValueError, ConfigError):
            # The configuration changed at runtime (no sign-in link, no base_url): the account stands, the application
            # issues the link with `POST …/signin-link` once it works again.
            link = {"url": None, "expires_at": None, "qr": None}
        return {"id": uid, "username": username, "signin_url": link["url"], "expires_at": link["expires_at"],
                "qr": link["qr"], "user": self.view(app, self.store.get_user(uid))}

    def _link_next(self, app: dict, value) -> Optional[str]:
        """Where the one-time link leads once the first sign-in is complete (T-94): the request's `next`, else the
        application's `welcome_url`, else None (the default target). A `next` outside the redirect circle
        (`config_check.link_next_ok`: a path, or the host of `base_url` or of `trusted_redirect_hosts`) is refused with
        400 `next_invalid` — never dropped in silence, so the application learns of its mistake."""
        if value is None or value == "":
            return app.get("welcome_url")
        if not config_check.link_next_ok(self.cfg, value):
            raise ProvisioningError("next_invalid", 400, "next: a path or an address on a trusted host")
        return value

    def _taken(self, app: dict, field: str) -> ProvisioningError:
        """The answer "taken" (409) — counted against `taken_per_hour` (429 beyond it) and logged, because a rate of
        them is how the operator sees a key that probes names."""
        self.auth.audit("provision_name_taken", None, None, f"app={app['id']} field={field}")
        self._spend_oracle(app)
        return ProvisioningError(f"{field}_taken", 409, field)

    def update(self, request: Request, app: dict, row, body: Any) -> dict:
        """`PATCH /auth/api/users/{id}` — `app` and the visible `row` were resolved before the body was read."""
        uid = int(row["id"])
        self.claim(request, app, write=True)
        self.not_deleting(row)
        b = self._fields(body, UPDATE_FIELDS)
        if not b:
            raise ProvisioningError("invalid", 400, "nothing to change: display_name, roles")
        display = None
        if "display_name" in b:
            display = self._display(b["display_name"])
            row = self.target(app, uid, whole=True)
        roles = self._roles(app, b["roles"], at_least_one=False) if "roles" in b else None
        if display is not None and display != row["display_name"]:
            self.store.set_display_name(int(row["id"]), display)
            self.auth.audit("provision_display_name", None, None, f"uid={int(row['id'])}")
        if roles is not None:
            self._panel().app_set_roles(int(row["id"]), app["roles"], roles)
        return self.view(app, self.store.get_user(int(row["id"])))

    def lock(self, request: Request, uid, lock: bool) -> dict:
        app = self.caller(request)
        self.need(app, "users:disable")
        row = self.target(app, uid, whole=True)
        self.claim(request, app, write=True)
        self.not_deleting(row)
        self.spend(app, "disable")
        try:
            outcome = self._panel().app_lock(int(row["id"]), lock)
        except HTTPException:
            raise ProvisioningError("not_found", 404)
        if outcome == "operator":
            raise ProvisioningError("disabled_by_operator", 409, "only the operator lifts this lock")
        return self.view(app, self.store.get_user(int(row["id"])))

    def link(self, request: Request, uid, raw: bytes = b"") -> dict:
        """`POST /auth/api/users/{id}/signin-link` — `raw` is the request body: empty, or a JSON object with `next`.
        Parsed only after the target is resolved: an account the application may not see answers 404 even with a
        broken body."""
        auth = self.auth
        app = self.caller(request)
        self.need(app, "users:invite")
        row = self.target(app, uid, whole=True)
        body: dict = {}
        if raw.strip():
            try:
                body = self._fields(json.loads(raw), LINK_FIELDS)
            except ValueError:
                raise ProvisioningError("invalid", 400, "a JSON object") from None
        target = self._link_next(app, body.get("next"))
        self.claim(request, app, write=True)
        self.not_deleting(row)
        if row["first_login_at"] is not None:
            # After the first sign-in a link from a key would be a takeover: from then on the person helps themselves
            # (sign-in link to their address, reset) or the operator does.
            raise ProvisioningError("already_signed_in", 409, "the account has signed in; a link would be a takeover")
        if row["disabled"]:
            raise ProvisioningError("account_disabled", 409, "unlock the account first")
        self.spend(app, "link")
        auth.store.revoke_user_magic_tokens(int(row["id"]))
        try:
            link = auth._signin_link(int(row["id"]), ttl_min=app["link_ttl_min"], app_id=app["id"], next=target)
        except (ValueError, ConfigError):
            # `magiclink_first_login_only`, a configuration changed at runtime, or a change between the checks above and here: no link, no text from inside.
            raise ProvisioningError("conflict", 409, "no sign-in link for this account now") from None
        return {"id": int(row["id"]), "signin_url": link["url"], "expires_at": link["expires_at"], "qr": link["qr"]}

    def delete(self, request: Request, uid) -> tuple[int, Optional[dict]]:
        """`DELETE /auth/api/users/{id}` — (status, body). An account that never signed in goes for good at once
        through `TinySesam.delete_user` (204: nothing to protect, and a typo is taken back cleanly); so does every
        account with `delete_grace_days=0`. Any other is locked with the application's mark (`disabled=3`, the effect
        of every lock: sessions, keys, devices, app passwords, open links) and gets `delete_after` = now + the grace
        period (202); its name stays taken until the cleanup (`gc`) deletes it through the same path. Asking again
        during the period changes nothing and answers the same. Counted against `delete_per_hour`/`delete_per_day`:
        a leaked key that deletes en masse meets a limit, and what it did stays restorable."""
        auth = self.auth
        app = self.caller(request)
        self.need(app, "users:delete")
        row = self.target(app, uid, whole=True)
        self.claim(request, app, write=True)
        target_id = int(row["id"])
        if row["delete_after"]:
            return 202, {"id": target_id, "state": "deleting", "delete_after": int(row["delete_after"])}
        self.spend(app, "delete")
        grace = int(app["delete_grace_days"])
        if row["first_login_at"] is None or grace == 0:
            try:
                gone = auth.delete_user(target_id)
            except StateError:
                raise ProvisioningError("conflict", 409, "the account cannot be deleted now") from None
            if not gone:
                raise ProvisioningError("not_found", 404)
            return 204, None
        until = _now() + grace * 86400
        if not self.store.schedule_deletion(target_id, until):
            # Deleted or scheduled by someone else between the check above and here.
            now = self.store.get_user(target_id)
            if now is None or not now["delete_after"]:
                raise ProvisioningError("not_found", 404)
            return 202, {"id": target_id, "state": "deleting", "delete_after": int(now["delete_after"])}
        keys = auth._lock_effects(target_id)
        auth.audit("provision_delete_scheduled", str(row["username"]), None,
                   f"uid={target_id} delete_after={until}" + (f" api_keys_revoked={keys}" if keys else ""))
        return 202, {"id": target_id, "state": "deleting", "delete_after": until}

    def restore(self, request: Request, uid) -> dict:
        """`POST /auth/api/users/{id}/restore` — take a deletion back within the grace period: `delete_after` goes,
        the application's lock is lifted (a lock of the operator stays). After the period the account answers 404
        like one that is gone; an account that is not being deleted → 409 `not_deleting`."""
        app = self.caller(request)
        self.need(app, "users:delete")
        row = self.target(app, uid, whole=True)
        self.claim(request, app, write=True)
        if not row["delete_after"]:
            raise ProvisioningError("not_deleting", 409, "the account is not being deleted")
        if not self.store.cancel_deletion(int(row["id"]), _now()):
            raise ProvisioningError("not_found", 404)
        self.auth.audit("provision_restore", str(row["username"]), None, f"uid={int(row['id'])}")
        return self.view(app, self.store.get_user(int(row["id"])))


def _safe(value) -> str:
    """A value for an audit detail: no spaces or control characters (the detail is `key=value` pairs)."""
    return "".join(z if z > " " and z != "\x7f" else "_" for z in str(value or ""))[:120] or "-"


# ---------- routes ----------

def register_routes(r, auth) -> None:
    """The routes of the account API on TinySesam's router (only when `apps` holds an application with
    `provisioning`). JSON only, `Cache-Control: no-store`, no CORS; errors as `{"error": <code>, "error_description":
    …}` like the approvals."""
    svc = auth._provisioning()

    def error(e: ProvisioningError) -> JSONResponse:
        body: dict = {"error": e.code}
        if e.detail:
            body["error_description"] = e.detail
        body.update(e.extra)
        headers = {"Cache-Control": "no-store"}
        if e.status == 429:
            headers["Retry-After"] = str(max(1, int(e.retry_after or 60)))
        return JSONResponse(body, status_code=e.status, headers=headers)

    def ok_json(data: dict, status: int = 200) -> JSONResponse:
        return JSONResponse(data, status_code=status, headers={"Cache-Control": "no-store"})

    async def body_of(request: Request):
        try:
            return await request.json()
        except Exception:
            raise ProvisioningError("invalid", 400, "a JSON object")

    @r.get("/auth/api/provisioning")
    def provisioning_info(request: Request):
        try:
            return ok_json(svc.info(request))
        except ProvisioningError as e:
            return error(e)

    @r.get("/auth/api/users")
    def provisioning_list(request: Request):
        try:
            return ok_json(svc.listing(request, dict(request.query_params)))
        except ProvisioningError as e:
            return error(e)

    @r.post("/auth/api/users")
    async def provisioning_create(request: Request):
        try:
            # The caller first: a request without a key gets 401, whatever its body.
            app = svc.caller(request)
            return ok_json(svc.create(request, app, await body_of(request)), 201)
        except ProvisioningError as e:
            return error(e)

    @r.get("/auth/api/users/{uid}")
    def provisioning_read(request: Request, uid: str):
        try:
            return ok_json(svc.read(request, uid))
        except ProvisioningError as e:
            return error(e)

    @r.patch("/auth/api/users/{uid}")
    async def provisioning_update(request: Request, uid: str):
        try:
            # Scope and target before the body is parsed: an account the application may not see answers 404 even
            # with a broken body.
            app = svc.caller(request)
            svc.need(app, "users:update")
            row = svc.target(app, uid)
            return ok_json(svc.update(request, app, row, await body_of(request)))
        except ProvisioningError as e:
            return error(e)

    @r.post("/auth/api/users/{uid}/disable")
    def provisioning_disable(request: Request, uid: str):
        try:
            return ok_json(svc.lock(request, uid, True))
        except ProvisioningError as e:
            return error(e)

    @r.post("/auth/api/users/{uid}/enable")
    def provisioning_enable(request: Request, uid: str):
        try:
            return ok_json(svc.lock(request, uid, False))
        except ProvisioningError as e:
            return error(e)

    @r.post("/auth/api/users/{uid}/signin-link")
    async def provisioning_link(request: Request, uid: str):
        try:
            # The body is optional (`{"next": …}`, T-94); `link` resolves caller and target before it parses it.
            return ok_json(svc.link(request, uid, await request.body()))
        except ProvisioningError as e:
            return error(e)

    @r.delete("/auth/api/users/{uid}")
    def provisioning_delete(request: Request, uid: str):
        try:
            status, data = svc.delete(request, uid)
        except ProvisioningError as e:
            return error(e)
        if data is None:
            return Response(status_code=status, headers={"Cache-Control": "no-store"})
        return ok_json(data, status)

    @r.post("/auth/api/users/{uid}/restore")
    def provisioning_restore(request: Request, uid: str):
        try:
            return ok_json(svc.restore(request, uid))
        except ProvisioningError as e:
            return error(e)
