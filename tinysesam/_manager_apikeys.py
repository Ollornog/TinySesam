"""The building block `apikeys` of `TinySesam`: machine access: API keys and service accounts, OAuth services, app passwords.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import json
import secrets
from . import _chain
from . import app_passwords as _ap
from . import passwords as _pw
from . import security
from .errors import ConfigError
from .passwords import hash_password
from typing import Optional
from typing import cast
from . import manager as _manager
from .manager import (
    _REQUEST,
    _valid_rules,
)


# ---------- API keys / service accounts (machine access, daemons) ----------
def create_service(self, username, roles=None, display_name=None) -> int:
    """Service/daemon account: no interactive login, API keys only. Roles = rights scope."""
    return self.create_user(username, is_service=True, roles=roles, display_name=display_name or username)


def create_api_key(self, user_id, name=None, expires_days=None, roles=None,
                   kind: str = "automation") -> dict:
    """Create a new API key. The return value contains 'key' in PLAINTEXT — only ONCE (afterwards only the hash).

    **Two kinds** (R6-5), because a key can be two quite different things:

    * ``kind="automation"`` (default) — a service, a script, a CI. It works alone,
      but **never carries the admin flag** of its owner and satisfies no route that demands
      admin. Up to 0.18.x a key of an admin was a full admin write API,
      without a second factor and without a CSRF layer: create users, set `is_admin`,
      reset passwords. A leaked CI key was thus the whole instance.
    * ``kind="human"`` — a tool that a person operates themselves. It applies **only
      together with a valid session of the same account**; in return it carries the full
      rights. Leaked on its own, it is worthless.

    A missing `expires_days` on an automation key is not without consequence: then
    `apikey_default_days` applies (default 90). `expires_days=0` means "unlimited" and needs
    `apikey_allow_unlimited=True` — a key without expiry outlives the person who
    issued it, and the project it was meant for.

    `roles` is a **scope**, not a rights increase: the list is trimmed to the owner's roles.
    A key can thus do less than its owner, never more.

    **If nothing is left after the trim, the method raises `ConfigError` and creates no
    key** — a typo in `roles` therefore yields an exception, not a key. Why not an
    empty scope: the reason is stated at the code below; it would reverse the effect.

    Returns `{"id", "key", "prefix", "expires_at", "roles", "dropped_roles", "kind"}`.
    `key` is the plaintext and is visible only this once; `dropped_roles` names what the
    trim removed (the same information is in the audit entry, there as
    `dropped_roles=`; up to 0.24.x the audit line said `verworfene_rollen=`, and up to 0.21.x the key
    here was named that way too).
    Until 2026-09-21 the list was taken over unchecked, and on checking it overwrote the
    roles of the account. Every signed-in user could thereby issue themselves arbitrary roles via the self-service route
    `POST /auth/apikeys` — invisibly, because the account in the
    database stayed role-less. In forward-auth operation the invented role went on as Remote-Group
    to the downstream app.
    """
    if kind not in self._KEY_KINDS:
        raise ConfigError(
            f"There is no API key kind {kind!r}. "
            "'automation' works on its own (without admin rights), 'human' only counts "
              "together with a session of the same account.")
    raw = "tsk_" + secrets.token_urlsafe(32)
    key_hash = self.store.token_digests(raw, "apikey")[0]   # keyed with the active pepper (T-72)
    prefix = raw[:12] + "…"
    # Expiry: 0 explicitly means "unlimited" and needs permission; None means
    # "not specified" and gets the default. Telling the two apart is the point —
    # before, `None` was silently unlimited, and that was the most common case.
    if expires_days is None:
        expires_days = int(self.cfg.apikey_default_days or 0)
    expires_days = int(expires_days)
    # Exactly ZERO means unlimited. A negative value is an expiry in the past,
    # i.e. a key dead from the start — that is not nonsense but the way to create a key
    # that is invalid at once (the suite uses it to test the expiry check itself).
    if expires_days == 0:
        if not self.cfg.apikey_allow_unlimited:
            raise ConfigError(
                "An API key without an expiry is a secret that nobody takes back — it "
                "outlives the person who issued it and the project it was meant "
                "for. Either set expires_days (default: "
                f"apikey_default_days={self.cfg.apikey_default_days}) or, if there really is "
                "no other way, apikey_allow_unlimited=True.")
        expires_at = None
    else:
        expires_at = _manager._now() + expires_days * 86400

    truncated = []
    if roles is not None:
        owner = self.store.get_user(user_id)
        permitted = set(self.user_roles(owner)) if owner else set()
        wished = [str(x) for x in roles]
        truncated = sorted(set(wished) - permitted)
        roles = sorted(set(wished) & permitted)
        # If NOTHING is left after trimming, the key must not come into being.
        #
        # The column `api_key.roles` knows only one empty value, and that means "no
        # scope, inherits the owner's roles". A scope shrunk to `[]` would thereby
        # turn into its opposite: whoever wants to scope a key to `["lagre"]` (a
        # typo) would get a key with ALL roles of the account. This trimming was
        # meant as a rights limitation and would have become a rights extension —
        # worse than before the fix.
        #
        # Hence an error instead of an assumption: only the caller knows what was meant.
        if not roles:
            raise ConfigError(
                f"API key scope {sorted(set(wished))} contains no role that the account "
                f"has ({sorted(permitted) or 'none'}). A key can only do less than "
                "its owner, never more - and an empty scope would mean "
                "'inherits everything' in the database. Either name an existing role or leave out `roles` "
                "(then the key inherits the account's roles).")

    kid = self.store.add_api_key(user_id, name, prefix, key_hash, roles, expires_at, kind=kind)
    detail = f"user={user_id} key={kid} name={name} kind={kind}"
    if expires_at is None:
        # Explicitly into the log: an unlimited key is a decision, not a
        # setting — whoever later asks "since when has this thing been lying around" finds something here.
        detail += " expiry=unlimited"
    if truncated:
        # Into the audit entry, not just discarded: whoever tries this should be visible.
        detail += f" dropped_roles={','.join(truncated)}"
    self.audit("apikey_create", self._account_name(user_id), detail=detail)
    self._security_event("api_key_created", user_id, key_id=kid, name=name or "")
    return {"id": kid, "key": raw, "prefix": prefix, "expires_at": expires_at,
            "roles": roles, "dropped_roles": truncated, "kind": kind}


def verify_api_key(self, key):
    """(user, key_roles|None) for a valid key, otherwise (None, None).

    The key's **kind** is afterwards in `self._last_key_kind` — `current_user()` needs
    it, and a third return value would have broken every foreign caller (M-4 freezes the
    surface for 1.0). Whoever wants to know the kind themselves uses `api_key_kind(key)`.
    `user` is an account dict as with `get_user()` (since 0.22.0; before, the database row).
    """
    self._last_key_kind = "automation"
    if not key or not key.startswith("tsk_"):
        return None, None
    digest = self.store.token_digest(key, "apikey")
    row = self.store.get_api_key_by_hash(digest)
    if not row:
        self._key_log(None, "unknown")
        return None, None
    # Found with a previous pepper (after `keys rotate --purpose oauth-pepper`): move it to the active one, so that
    # retiring the old pepper does not cut it (T-72).
    self.store.rewrite_api_key_digest(digest, self.store.token_digests(key, "apikey")[0])
    if row["revoked"]:
        self._key_log(row, "revoked")
        return None, None
    if row["expires_at"] and row["expires_at"] < _manager._now():
        self._key_log(row, "expired")
        return None, None
    u = self.store.get_user(row["user_id"])
    if not u or u["disabled"]:
        self._key_log(row, "account_locked")
        return None, None
    rests = self._key_rests(u)
    if rests:
        self._key_log(row, rests)
        return None, None
    self.store.touch_api_key(row["id"])
    self._key_log(row, None)
    self._last_key_kind = self._key_kind(row)
    try:
        kr = json.loads(row["roles"] or "[]")
    except Exception:
        kr = []
    return self._as_dict(u), (kr or None)


def _key_rests(self, u) -> Optional[str]:
    """Are this account's API keys dormant because the identity provider does not (or no longer) back it?
    Returns: the reason (`idp_no`, `idp_unconfirmed`) or None (finding 8).

    Only for accounts with an OIDC binding, and only as long as OIDC is set up — without a provider
    there would be nobody who could confirm, and every key would be dead after the deadline.

    * **No from the provider** (`idp_confirmed_at = 0`, set by the re-check 4a): the
      session ended there already; without this check an automation key kept working for up to
      `apikey_default_days` — the same flaw PocketID itself had until 2.5.0
      (CVE-2026-43983: a locked account keeps access via an old token).
    * **No confirmation within `oidc_apikey_confirm_days`**: whoever works only by script
      has no session that 4a re-checks. This way an account locked at the provider is noticed at
      the latest after the deadline.

    Nothing is deleted: `invalid_grant` does not distinguish between "locked" and "merely
    expired" (RFC 6749 5.2) — the next sign-in via the provider wakes the keys."""
    if self.oidc is None:
        return None
    try:
        state = u["idp_confirmed_at"]
    except (IndexError, KeyError):
        return None                       # a row without the column (a dict from own code)
    if not self.store.is_oidc_account(u["id"]):
        return None
    if int(state if state is not None else 1) <= 0:
        return "idp_no"
    deadline = int(self.cfg.oidc_apikey_confirm_days or 0) * 86400
    if deadline and (state is None or _manager._now() - int(state) > deadline):
        return "idp_unconfirmed"
    return None


def _idp_no(self, user_id, name, ip, client, reason) -> None:
    """The provider said no (4a): the session has already ended — now the
    keys go dormant too (finding 8). One line in the audit log says how many it affects."""
    self.store.idp_refused(user_id)
    active = [k for k in self.store.list_api_keys(user_id) if not k["revoked"]]
    if active:
        self.store.audit_log("api_keys_dormant", name, ip,
                             f"client={client} reason={reason} count={len(active)}")


def _once_per(self, key_name, window_sec: float) -> bool:
    """True if `key_name` has not yet been logged within the window — and remembers it in advance.

    For events that come in bursts (key use, rejected forward auth). Per process;
    several workers therefore each write one line, which is deliberately cheaper than a reconciliation.
    """
    now = _manager._now()
    if now - self._log_throttle.get(key_name, 0) < window_sec:
        return False
    if len(self._log_throttle) >= self._THROTTLE_MAX:
        self._log_throttle.clear()   # cap: whoever probes addresses does not fill memory
    self._log_throttle[key_name] = now
    return True


def _key_log(self, row, reason: Optional[str]) -> None:
    """Log a key use (`reason=None`) or rejection (`reason=<reason>`) — throttled (B5-05).

    Until here the system knew only `last_used` of a key: no who, no from where, and
    a rejected key left nothing at all. That is exactly the signal, though — a
    revoked key that keeps knocking means: it is still lying around somewhere, or it has
    leaked. The IP comes from the running request (`_REQUEST`).
    """
    a = _REQUEST.get() or {}
    ip = a.get("ip")
    kid = row["id"] if row is not None else None
    if not self._once_per(("apikey", kid, ip, reason), self._APIKEY_AUDIT_WINDOW):
        return
    owner = self._account_name(row["user_id"]) if row is not None else None
    kind = self._key_kind(row) if row is not None else "?"
    if reason is None:
        self.store.audit_log("apikey_use", owner, ip, f"key={kid} kind={kind}")
        return
    detail = f"key={kid} reason={reason}" if kid is not None else f"reason={reason}"
    self.store.audit_log("apikey_denied", owner, ip, detail)
    security.seclog.warning("api key denied user=%s ip=%s reason=%s",
                            security.for_log(owner or "-"), security.for_log(ip), reason)


def api_key_kind(self, key) -> str:
    """The kind of a key (`"automation"`/`"human"`) — without using it. `""` for an unknown key."""
    row = self.store.get_api_key_by_hash(self.store.token_digest(key or "", "apikey"))
    return self._key_kind(row) if row else ""


def list_api_keys(self, user_id) -> list:
    """The API keys of an account — without the secrets themselves, which exist only once at
    issuance. One dict per key (columns of `api_key`), `kind` with its English name (schema 12;
    up to 0.21.x the database row with the stored value)."""
    return [{**dict(k), "kind": self._key_kind(k)} for k in self.store.list_api_keys(user_id)]


def revoke_api_key(self, key_id, user_id=None):
    """Revoke a key. It stays in the list — whoever issued it should see that."""
    owner = self.store.api_key_owner(key_id)
    before = self.store.count_active_api_keys(owner) if owner is not None else 0
    self.store.revoke_api_key(key_id, user_id)
    self.audit("apikey_revoke", self._account_name(owner), detail=f"key={key_id}")
    if owner is not None and self.store.count_active_api_keys(owner) < before:
        self._security_event("api_key_revoked", owner, key_id=key_id)


def _keys_revoked(self, user_id, reason: str) -> int:
    """Revoke every standing credential of an account — and notify the owner (limit e).

    THE one revocation point for reset, lockout, admin password and `sessions/revoke` (`reason` is one of
    `_KEYS_REVOKED_REASONS`): API keys, app passwords (T-66), services (T-60) and connected devices (OAuth
    grants with their refresh and access tokens, T-36). Sessions and open links stay with the callers — "end
    others" keeps the current session, a lockout keeps nothing. A new kind of credential is revoked HERE, not at
    each caller: until the attack round of 2026-11-21 (A-1) only the lockout ended the OAuth grants, and a
    password reset or "end all sessions" left an MCP client connected for up to the refresh lifetime.
    Returns the number of API keys (the callers' audit lines and JSON answers name that count)."""
    if reason not in self._KEYS_REVOKED_REASONS:
        raise ValueError(f"unknown reason {reason!r} — allowed: {self._KEYS_REVOKED_REASONS}")
    n = self.store.revoke_user_api_keys(user_id)
    if n:
        self._security_event("api_keys_revoked", user_id, count=n, reason=reason)
    # The app passwords (T-66) go the same way: they are a second way in as much as a key is.
    self._app_passwords_revoked(user_id, reason)
    # And the services (T-60): a service paired to the account is the machine version of a key.
    self._services_revoked(user_id, reason)
    # And the connected devices (OAuth, T-36): a refresh token is a key with a longer life (A-1). Each grant
    # writes `oauth_revoked` to the audit log and `oauth_device_revoked` (with this `reason`) to the hook.
    self._oauth_revoke_user(int(user_id), reason)
    return n


def _services_revoked(self, user_id, reason: str) -> int:
    """Revoke every service (T-60) of an account — also with the switch off, for what is left."""
    if not self.store.oauth_service_ids(int(user_id)):
        return 0
    from .oauth_services import ServiceClients
    srv = self._oauth_server()
    return (srv.services or ServiceClients(srv)).revoke_user(int(user_id), reason)


# ---------- Services: OAuth client_credentials + private_key_jwt (T-60, ADR-13) ----------
def _services(self):
    if not (self.cfg.oauth_enabled and self.cfg.oauth_service_clients):
        raise ConfigError("Services need oauth_enabled=True and oauth_service_clients=True.")
    return self._oauth_server().services


def create_service_pairing(self, user_id, name=None, resources=None, roles=None) -> dict:
    """A one-time pairing code for a service that will act as `user_id` (a service account or a person's own
    account — never with the admin flag). The service redeems it with `tinysesam-client pair <base_url> <code>`.

    `resources`: the resources (from `oauth_resources`) it may get tokens for — may be left out when exactly
    one is configured. `roles`: a scope, trimmed to the account's roles like an API key's; nothing left raises
    `ConfigError`. Lives `oauth_pairing_minutes`, single use, only its digest is stored, and it goes with the
    account's other open links on a lock or password reset.

    Returns `{"code", "expires_at", "resources", "roles", "dropped_roles", "pair_url", "issuer"}` — `code` only
    this once. Who may call it is the caller's decision: the built-in routes allow it for the own account
    from a freshly confirmed session and for any account in the admin panel."""
    request = _REQUEST.get() or {}
    return self._services().issue_pairing(int(user_id), name=name, resources=resources, roles=roles,
                                          actor=request.get("actor"), ip=request.get("ip"))


def list_service_clients(self, user_id=None) -> list:
    """The live services — of one account or all: client ID, name, account, roles, resources, created, last
    token request and address, and the keys (`kid`, created, expiry, end of the rotation overlap, last use)."""
    return self._services().listing(user_id)


def revoke_service_client(self, client_id, user_id=None) -> bool:
    """Revoke a service at once: its keys are deleted, its tokens stop working with the next request. With
    `user_id` only a service of that account. True if one was live."""
    svc = self.store.oauth_service(client_id)
    if svc is None or (user_id is not None and int(svc["user_id"]) != int(user_id)):
        return False
    from .oauth_services import ServiceClients
    srv = self._oauth_server()
    request = _REQUEST.get() or {}
    # With `user_id` the holder revokes their own; without it an operator (panel, own code) does.
    return (srv.services or ServiceClients(srv)).revoke(str(client_id), "user" if user_id is not None else
                                                        "admin", request.get("ip"))


def create_app_password(self, user_id, name, hosts=None, expires_days=None) -> dict:
    """Create an app password (T-66) for HTTP clients that speak only Basic auth — WebDAV, CalDAV/CardDAV, Git
    over HTTPS. The return value carries it in PLAIN TEXT under `secret`, this once; only an HMAC digest
    with the pepper keyring (ADR-12) is stored.

    `name` (required): the device or purpose ("Phone calendar"). `hosts`: the applications it is valid for,
    from `app_password_hosts()`; None is allowed only when exactly one application accepts app passwords —
    otherwise the caller chooses (one is the default in the account page: an app password is bound as
    narrowly as its use). `expires_days`: None → `app_password_default_days`; 0 → no expiry, only with
    `app_password_allow_unlimited`.

    It works ONLY at the gate (`/auth/forward`) of the chosen hosts, carries the account's roles but never its
    admin flag, and is revoked with the API keys when the account is locked, its password is reset or "sign
    out everywhere" is pressed. Raises `ConfigError` for an unusable request (no name, unknown host, expiry
    not allowed, account unknown or locked) — nothing is created then.

    The route `POST /auth/app-passwords` asks for a fresh confirmation first (`_require_fresh`, B-12): an app
    password is lasting access to the account. Whoever calls this method from own code owns that check.
    Returns `{"id", "secret", "name", "hosts", "expires_at"}` — `secret`, not `password`: it is a generated
    token of 124 bits, not a person's password (a fast keyed digest is right for it, a slow KDF is not needed)."""
    apps = {a["host"] for a in self.app_password_hosts()}
    if not apps:
        raise ConfigError("No application accepts app passwords: set forward_apps[host]['app_passwords'] = True "
                          "(with forward_auth_enabled).")
    label = "".join(c for c in str(name or "") if c >= " " and c != "\x7f").strip()
    if not label:
        raise ConfigError("An app password needs a name — the device or purpose it is for.")
    if len(label) > _ap.MAX_NAME:
        raise ConfigError(f"The name of an app password has at most {_ap.MAX_NAME} characters.")
    if hosts is None:
        if len(apps) != 1:
            raise ConfigError("Choose the applications this app password is for: "
                              + ", ".join(sorted(apps)) + ".")
        chosen = sorted(apps)
    else:
        if isinstance(hosts, str):
            hosts = [hosts]
        chosen = sorted({str(h).strip().lower().rstrip(".") for h in hosts})
        if not chosen or any(h not in apps for h in chosen):
            raise ConfigError("An app password is valid only for applications that accept app passwords: "
                              + ", ".join(sorted(apps)) + ".")
    u = self.store.get_user(user_id)
    if not u or u["disabled"]:
        raise ConfigError("No such account, or it is locked.")
    days = int(self.cfg.app_password_default_days if expires_days is None else expires_days)
    if days == 0:
        if not self.cfg.app_password_allow_unlimited:
            raise ConfigError("An app password without expiry outlives the device it was typed into — choose "
                              f"a lifetime (at most {_ap.MAX_DAYS} days) or ask the operator for "
                              "app_password_allow_unlimited=True.")
        expires_at = None
    elif 0 < days <= _ap.MAX_DAYS:
        expires_at = _manager._now() + days * 86400
    else:
        raise ConfigError(f"The lifetime of an app password is 1 to {_ap.MAX_DAYS} days.")
    secret = _ap.generate()
    key = self._pepper_keyring.active
    digest = _ap.digest(key.material, cast(str, _ap.normalize(secret)))
    pid = self.store.app_password_add(int(u["id"]), label, digest, key.kid, chosen, expires_at,
                                      self._request_ip())
    self.audit("app_password_create", str(u["username"]),
               detail=f"id={pid} hosts={','.join(chosen)}"
               + (" expiry=unlimited" if expires_at is None else f" days={days}"))
    self._security_event("app_password_created", int(u["id"]), app_password_id=pid, name=label,
                         hosts=list(chosen))
    return {"id": pid, "secret": secret, "name": label, "hosts": chosen, "expires_at": expires_at}


def list_app_passwords(self, user_id=None) -> list:
    """The app passwords of an account (`user_id=None`: of all accounts) — never a secret or digest. One dict
    each: `id`, `username`, `name`, `hosts`, `created_at`, `expires_at`, `last_used`, `last_ip`, `revoked`,
    `revoked_reason`, `expired`. Revoked and expired ones stay in the list: the holder should see them."""
    now = _manager._now()
    out = []
    for r in self.store.app_passwords(user_id):
        try:
            hosts = [str(h) for h in json.loads(r["hosts"] or "[]")]
        except ValueError:
            hosts = []
        out.append({"id": r["id"], "username": r["username"], "name": r["name"], "hosts": hosts,
                    "created_at": r["created_at"], "expires_at": r["expires_at"], "last_used": r["last_used"],
                    "last_ip": r["last_ip"], "revoked": r["revoked_at"] is not None,
                    "revoked_reason": r["revoked_reason"] or "",
                    "expired": bool(r["expires_at"] and r["expires_at"] <= now)})
    return out


def revoke_app_password(self, pw_id, user_id=None, by_operator: bool = False) -> bool:
    """Revoke one app password — of `user_id` only, if given (the account page). True if it was valid until
    now. It stays in the list as revoked. Audit `app_password_revoke`, event `app_password_revoked`."""
    row = self.store.app_password(int(pw_id))
    if row is None or (user_id is not None and int(row["user_id"]) != int(user_id)):
        return False
    if not self.store.app_password_revoke(int(pw_id), "admin" if by_operator else "holder", user_id):
        return False
    self.audit("app_password_revoke", self._account_name(row["user_id"]), detail=f"id={int(pw_id)}")
    self._security_event("app_password_revoked", int(row["user_id"]), app_password_id=int(pw_id))
    return True


def _app_passwords_revoked(self, user_id, reason: str) -> int:
    """Revoke every valid app password of an account — with the API keys (`_keys_revoked`), same reasons."""
    n = self.store.app_passwords_revoke_all(int(user_id), reason)
    if n:
        self.audit("app_passwords_revoked", self._account_name(user_id), detail=f"count={n} reason={reason}")
        self._security_event("app_passwords_revoked", int(user_id), count=n, reason=reason)
    return n


def _app_password_user(self, request, url: str) -> tuple:
    """The account behind `Authorization: Basic` at the gate for `url` (T-66) — `(account | None, outcome)`.

    `outcome` is `""` when there is no usable Basic header (the caller carries on as without credentials),
    `"ok"`, or the reason of a refusal. Called only for a host whose `forward_apps` entry allows app passwords.

    * The password must have the shape of an app password (`app_passwords.normalize`); the account's own
      password never has to be compared with anything — it cannot pass, and TOTP cannot be bypassed by it.
    * The digest is looked up with every pepper of the keyring; the row must belong to the named account
      (name or address, as at sign-in), name this host, be neither revoked nor expired, and the account must
      be active (and backed by its identity provider, like an API key, `_key_rests`).
    * A guess (wrong secret, the account's own password, an app password of another account or for another
      application) is a failed sign-in: booked in its own bucket (`security.SIGN_IN_OWN_LOCK`), `failed login`
      in the security log (fail2ban). A known app password that was revoked or has expired is no guess — the
      device still has it: refused and audited, but not booked, so an old phone cannot lock its owner out.
    * Success: the account with `is_admin` cleared (an app password never carries admin rights, like an
      automation key), `_via = "app_password"`."""
    from urllib.parse import urlsplit
    creds = _ap.parse_basic(request.headers.get("authorization", ""))
    if creds is None:
        return None, ""
    username, secret = creds
    ip = self.client_ip(request)
    host = (urlsplit(url or "").hostname or "").lower().rstrip(".")
    normalized = _ap.normalize(secret)
    row, used_key = None, None
    if normalized is not None:
        for key in self._pepper_keyring.keys:
            row = self.store.app_password_by_digest(_ap.digest(key.material, normalized))
            if row is not None:
                used_key = key
                break
    account = self.find_user(username)
    if row is not None and account is not None and int(account["id"]) == int(row["user_id"]):
        stale = None
        if row["revoked_at"] is not None:
            stale = "revoked"
        elif row["expires_at"] and int(row["expires_at"]) <= _manager._now():
            stale = "expired"
        elif account["disabled"]:
            stale = "account_locked"
        else:
            stale = self._key_rests(self.store.get_user(int(account["id"])))
        if stale:
            self._app_password_log(row, account, ip, stale, host)
            return None, stale
        try:
            hosts = {str(h) for h in json.loads(row["hosts"] or "[]")}
        except ValueError:
            hosts = set()
        if host in hosts:
            if self._is_app_password_locked(username, ip):
                return None, "locked"
            now = _manager._now()
            active = self._pepper_keyring.active
            moved = used_key is not None and used_key.kid != active.kid
            if moved or not row["last_used"] or now - int(row["last_used"]) >= self._APP_PASSWORD_TOUCH_SEC \
                    or row["last_ip"] != ip:
                self.store.app_password_used(
                    int(row["id"]), ip, now,
                    digest=_ap.digest(active.material, cast(str, normalized)) if moved else None,
                    kid=active.kid if moved else None)
            self._app_password_log(row, account, ip, None, host)
            d: dict = dict(self._as_dict(self.store.get_user(int(account["id"]))) or {})
            d["is_admin"] = 0
            self._strip_delegate_roles(d)       # nor a delegate role (T-74)
            d["_via"] = "app_password"
            d["_app_password_id"] = int(row["id"])
            return d, "ok"
        reason = "wrong_app"
    elif normalized is None:
        reason = "not_app_password"
    else:
        reason = "unknown"
    # A guess: book it — atomically, in the bucket of its own — and say so.
    attempt = self._begin_attempt(username, ip, "app_password")
    if attempt is None:
        return None, "locked"
    self._record_login(username, ip, False, "app_password", attempt=attempt)
    self._app_password_log(row if reason == "wrong_app" else None, account, ip, reason, host)
    return None, reason


def _is_app_password_locked(self, username, ip) -> bool:
    """The bucket of the app passwords (T-66, `security.SIGN_IN_OWN_LOCK`): pair, account and address, counted
    only over `app_password` — separate from the login lockout and the streak. Read-only; a refusal is
    reported as `failed login … reason=lockout_app_password…` (`_rejected`)."""
    for reason, limit, filt in _valid_rules(self._rules(username, ip, "app_password")):
        if self.store.count_fails(**filt, only_confirmed=True) >= limit:
            self._rejected(username, ip, reason, login=True)
            return True
    return False


def _app_password_log(self, row, account, ip, reason: Optional[str], host: str) -> None:
    """Audit an app-password use (`reason=None`) or refusal — throttled per row (or account), IP and outcome."""
    pid = int(row["id"]) if row is not None else None
    owner = str(account["username"]) if account is not None else None
    if not self._once_per(("app_password", pid, owner, ip, reason), self._APP_PASSWORD_AUDIT_WINDOW):
        return
    where = f" host={host}" if host else ""
    if reason is None:
        self.store.audit_log("app_password_use", owner, ip, f"id={pid}{where}")
        return
    self.store.audit_log("app_password_denied", owner, ip,
                         (f"id={pid} " if pid is not None else "") + f"reason={reason}{where}")


def set_password(self, user_id, password, *, by_operator: bool = False):
    """Set an account's password (without checking the old one — that is the caller's business).

    The password rule (`password_policy_error`) does **not** check here — the setters do
    (registration, reset, account page, admin panel, CLI), because only they can give a
    readable answer. Whoever calls this method from their own code first asks `password_policy_error()`.
    Notification always happens (`password_changed`), whichever way it is reached.

    `by_operator=True`: an administrator sets the password of SOMEONE ELSE (panel: new account,
    reset). Then it is a start secret (T-46, ASVS 6.4.1): with `admin_password_must_change` the
    next password sign-in stays half until the holder has chosen an own one, and the event says
    `by_operator` (the owner gets a mail with `notify_new_access`). Every other call is the
    holder's own password and clears that mark."""
    self.store.set_password_hash(user_id, hash_password(password))
    self.store.set_password_must_change(user_id, bool(by_operator and self.cfg.admin_password_must_change))
    self._security_event("password_changed", user_id, by_operator=bool(by_operator))


def password_policy_error(self, password, *, username=None, email=None, api: bool = False) -> Optional[str]:
    """The password rule for a NEW password — `None` means "fine", otherwise the
    translated reason (`api=True`: the text for a JSON response).

    One rule for all setters: registration, password reset, account page and the
    admin panel (there every check was missing until T-13, finding B2-13). It checks minimum
    (`password_min_length`) and maximum length (R4-07), the built-in plus the custom
    blocklist and context-related words — service name (`rp_name`), username and the
    local part of the email address (B2-5/H-17). Details: `passwords.password_defect`."""
    context = [self.cfg.rp_name, username or ""]
    if email:
        context.append(str(email).split("@", 1)[0])
    finding = _pw.password_defect(password or "", self._password_min_length(),
                                 context=context, blocklist=self._blocklist)
    if finding is None:
        return None
    reason, values = finding
    key_name = {"short": ("api.password_short", "err.pw_short"),
                  "long": ("api.password_long", "err.pw_long"),
                  "weak": ("api.password_weak", "err.pw_weak")}[reason]
    return self.t(key_name[0] if api else key_name[1], **values)


def _password_alone_possible(self) -> bool:
    """Can the password, in this configuration, sign in COMPLETELY on its own?

    Yes in classic mode (no `login_chain`): an account without TOTP signs in with the
    password alone — and a TOTP can be removed again later. Yes also for a
    chain that demands nothing besides the password. No only when the global chain enforces a
    further factor (`["password", "totp"]`, `["oidc", "password"]`).

    Deliberately a statement about the CONFIGURATION, not about the individual account: whoever has
    TOTP today can remove it tomorrow, and the password would be left standing alone
    with the shorter length.

    And only with `mfa_enrollment="strict"`: with `"first_login"` (default) and `"grace"` an
    account sets up the demanded second factor itself the first time — whoever knows only the password
    then binds their own authenticator and is in. Exactly the initial passwords
    (panel, invitation, registration) thus sign in alone in this window (measured in the
    attack on B2-4). Only when the operator grants the enrolment is the password never
    alone. Limit: a window opened by the operator (`grant_mfa_enrollment`) — that is
    their deliberate decision for exactly one account."""
    chain = list(self.cfg.login_chain or ())
    if not chain or _chain.satisfied(chain, ["password"], False):
        return True
    return self.cfg.mfa_enrollment != "strict"


def _password_min_length(self) -> int:
    """The minimum length for a NEW password (B2-4, NIST SP 800-63B-4, 3.1.1.2).

    The standard demands 15 characters if the password can sign in alone, and 8 if it is only
    part of a sign-in with a further factor. Both values can be set in the panel
    (`password_min_length_single_factor`, `password_min_length`); whoever does not want the stricter
    rule sets the first to 8. Existing passwords remain valid — the rule applies
    where a password is set."""
    base = self._sec("password_min_length")
    if self._password_alone_possible():
        return max(base, self._sec("password_min_length_single_factor"))
    return base
