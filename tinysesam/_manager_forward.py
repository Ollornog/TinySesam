"""The building block `forward` of `TinySesam`: forward auth for the reverse proxy and per-application approvals.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

from . import security
from .store import role_invalid
from fastapi import HTTPException
from fastapi import Request
from typing import Optional
from . import manager as _manager


def _forward_response_headers(self, user, host: str = "") -> dict:
    """The headers the proxy passes on to the app on a successful check.

    `config.forward_headers` is the **complete** list, not an addition: whoever sets only
    `{"user": "X-WEBAUTH-USER"}` also sends only that one header — so "I do not want to
    give out the email address" is an omission and not a second switch. A field may
    point to several names if an app reads one and an intermediary the other.
    """
    if any(z < " " or z == "\x7f" for z in str(user["username"] or "")):
        # The cleaning below would remove the character and send the name of ANOTHER
        # account (`boss\x01` → `boss`). Fail-closed: better no approval than a
        # foreign identity. Exactly the characters that `_header_value` removes (C0, DEL) — a
        # ZWNJ in a Persian existing name passes through losslessly and does not collide
        # (counter-check). `create_user` no longer permits new names like that at all.
        security.seclog.warning("forward-auth rejected: account name with control characters (user_id=%s)",
                                user["id"])
        raise HTTPException(403, self.t("api.name_invalid"))
    values = self._forward_values(user, host)
    out = {}
    for slot, names in self._forward_header_map().items():
        for name in ([names] if isinstance(names, str) else names):
            out[name] = self._header_value(values[slot])
    return out


def _forward_header_map(self) -> dict:
    """slot → header name(s): `config.forward_headers` (or the default), plus every mandatory slot it leaves out
    under its default name (`FORWARD_HEADERS_MANDATORY`)."""
    fields = dict(self.cfg.forward_headers or self.FORWARD_HEADERS_DEFAULT)
    for slot in self.FORWARD_HEADERS_MANDATORY:
        fields.setdefault(slot, self.FORWARD_HEADERS_DEFAULT[slot])
    return fields


def _account_kind(self, user) -> str:
    """`service` or `user` from `is_service` — exactly 0 or 1 (an int or a bool). Anything else, or a missing
    field, is refused with 403 and a security log line: failing closed, never guessed as `user` (like a name with
    control characters)."""
    try:
        raw = user["is_service"]
    except (KeyError, IndexError, TypeError):
        raw = None
    if type(raw) in (int, bool) and raw in self._ACCOUNT_KINDS:
        return self._ACCOUNT_KINDS[int(raw)]
    security.seclog.warning("forward-auth rejected: unexpected account kind (user_id=%s)",
                            user["id"] if isinstance(user, dict) else "?")
    raise HTTPException(403, self.t("api.kind_invalid"))


def _app_of_host(self, host: str) -> Optional[str]:
    """The id of the application in `apps` whose `hosts` name `host` (T-101) — or None. Read at request time."""
    host = str(host or "").strip().lower().rstrip(".")
    apps = self.cfg.apps if isinstance(getattr(self.cfg, "apps", None), dict) else {}
    for app_id, entry in apps.items():
        if isinstance(entry, dict) and isinstance(entry.get("hosts"), list) and host in entry["hosts"]:
            return app_id
    return None


def _forward_values(self, user, host: str = "") -> dict:
    """The values behind the forward-auth headers and the claims of the gate token — ONE source,
    so that the proxy passes on the same identity on both routes.

    `perms` (T-101): the account's permissions for the application of `host` (`apps[id].hosts`), joined with `,`;
    empty for a host of no application. A set longer than `PERMISSIONS_VALUE_MAX` bytes is refused with 403 — never
    cut, a cut list would be another set of rights.

    An account that still holds a role which cannot travel as one role (T-85, `store.role_invalid` — stored by an
    older version or a raw write) is refused with 403, like an account name with a control character: stripping
    would turn `ad\\x01min` into `admin`, and a comma would split one role into two."""
    bad = [r for r in self.user_roles(user) if role_invalid(r)]
    if bad:
        security.seclog.warning("forward-auth rejected: role name with a comma, a control character or surrounding "
                                "spaces (user_id=%s)", user["id"])
        raise HTTPException(403, self.t("api.role_invalid"))
    return {
        "id": str(user["id"]),
        "user": str(user["username"] or ""),
        "name": str(user["display_name"] or user["username"] or ""),
        "email": str(user["email"] or ""),
        "groups": ",".join(self.user_roles(user) + (["admin"] if user["is_admin"] else [])),
        "auth": self._FORWARD_AUTH_KINDS.get(str(user.get("_via") or ""), "") if isinstance(user, dict) else "",
        "kind": self._account_kind(user),
        # Only when the slot is sent: an own `forward_headers` without `perms` is never refused for the set's size.
        "perms": self._forward_permissions(user, host) if "perms" in self._forward_header_map() else "",
    }


def _forward_permissions(self, user, host: str) -> str:
    """`Remote-Permissions` / `ts_perms` for `host` — see `_forward_values`."""
    app = self._app_of_host(host) if host else None
    if app is None:
        return ""
    value = ",".join(self.permissions_of(user, app=app))
    if len(value.encode("utf-8")) > self.PERMISSIONS_VALUE_MAX:
        security.seclog.warning("forward-auth rejected: %d bytes of permissions for app=%s exceed %d — assign fewer "
                                "(user_id=%s)", len(value.encode("utf-8")), app, self.PERMISSIONS_VALUE_MAX, user["id"])
        raise HTTPException(403, self.t("api.permissions_too_large"))
    return value


def gate_public_key(self) -> str:
    """The public key of the ACTIVE gate key (ADR-9): 32 raw bytes, Base64 — the value for
    `sign_key` in Caddy's `jwtauth` (with `sign_alg EdDSA`). Public, no secret.

    Since T-48 the gate key is a key of its own (`TINYSESAM_GATE_KEY`, `gate_key_file`, otherwise kept in the
    database); `tinysesam keys rotate --purpose gate` changes it. A proxy with `jwk_url` follows by itself
    (`gate_jwks`); one with `sign_key` needs this value anew after a rotation."""
    from . import gate as _gate
    return _gate.public_b64(self._gate_key_name)


def gate_jwks(self) -> dict:
    """The public gate keys as a JSON Web Key Set (RFC 7517/8037) — the active key and the previous ones
    within their overlap (`keys.GATE_OVERLAP_SEC`, the longest a token lives). Served at
    `/auth/gate/jwks.json` for caddy-jwt's `jwk_url`: a rotation then needs no change at the proxy, and tokens
    signed before it stay valid until they expire. Public, no secret."""
    from . import keys as _keys
    return _keys.jwks(self._gate_keyring, _manager._wall_now())


def _approval_ring(self):
    """The keyring of purpose `approval` (`TINYSESAM_APPROVAL_KEY`, `approval_key_file`, else the database)."""
    from . import keys as _keys
    if self._approval_keyring is None:
        self._approval_keyring = _keys.load_stored(_keys.APPROVAL, self.store,
                                                   str(getattr(self.cfg, "approval_key_file", "") or ""))
    return self._approval_keyring


def _approval_private(self):
    """The active approval signing key (Ed25519) — only `Approvals._confirmation` signs with it."""
    from . import keys as _keys
    return _keys.gate_private(self._approval_ring().active.material)


def approval_jwks(self) -> dict:
    """The public keys of the approval confirmations as a JSON Web Key Set (RFC 7517/8037): the active key and the
    previous ones within `keys.APPROVAL_OVERLAP_SEC`. Served at `/auth/approvals/jwks.json` for the applications
    that check confirmations (`tinysesam.approval_token.verify`). A set of its own — never the gate keys. Public,
    no secret."""
    from . import keys as _keys
    return _keys.jwks(self._approval_ring(), _manager._wall_now())


def gate_issuer(self) -> str:
    """`iss` of the gate tokens: `base_url` without a trailing slash, without it `"tinysesam"`.
    Fixed rather than derived from the request — the proxy compares it with its configuration."""
    return (security.normalize_base(str(self.cfg.base_url or "").strip()) or "").rstrip("/") or "tinysesam"


def _gate_hosts(self) -> set:
    """Hosts for which a gate token is issued: the protected ones (`trusted_redirect_hosts`,
    `oidc_clients`) and the own one from `base_url`. Not for any other — `X-Forwarded-Host`
    comes from the caller, and a token for a host that this installation does not protect at all
    would have no purpose except an attacker's."""
    from urllib.parse import urlsplit
    hosts = {str(h).strip().lower().rstrip(".") for h in (self.cfg.trusted_redirect_hosts or []) if h}
    hosts |= {str(h).strip().lower().rstrip(".") for h in (self.cfg.oidc_clients or {}) if h}
    own = urlsplit(self.gate_issuer()).hostname
    if own:
        hosts.add(own.lower())
    return hosts


def _gate_link_session(self, request, host: str):
    """The session row behind the connection cookie of this app host (T-26) — or None.

    The cookie applies only to the host for which it was issued: the row in `gate_link` carries
    it, and a cookie that turns up at another host finds nothing. The session itself is checked
    with the same rules as via the own cookie (expiry, inactivity, OIDC re-check)."""
    if not self.cfg.gate_link_enabled or not host:
        return None
    raw = request.cookies.get(self._GATE_LINK_COOKIE) or ""
    if not raw:
        return None
    handle = self.store.gate_link_handle(self.store.session_hash(raw), host)
    if not handle:
        return None
    s = self.store.get_session_by_handle(handle)
    if s is not None and not self._oidc_recheck(s):
        return None
    return s


def _gate_session(self, request, host: str = ""):
    """The session of this request for the gate: the own cookie, otherwise the host's connection."""
    return self._session_from_request(request) or self._gate_link_session(request, host)


def _gate_set_cookie(self, response, name: str, value: str, max_age: int) -> None:
    """A host-only cookie under `__Host-` — Secure, Path=/, without Domain (otherwise the
    browser discards it). With `max_age=0` it deletes."""
    response.headers.append("set-cookie", f"{name}={value}; Path=/; Max-Age={int(max_age)}; "
                                          "Secure; HttpOnly; SameSite=Lax")


def _gate_link_url(self, host: str, orig_url: str, request=None) -> str:
    """Where an app host without a connection is sent: to ITS `/.tinysesam/start` (T-26)."""
    from urllib.parse import quote, urlsplit
    o = urlsplit(orig_url or "")
    schema = o.scheme if o.scheme in ("http", "https") else "https"
    netloc = o.netloc or host
    rest = (o.path or "/") + (("?" + o.query) if o.query else "")
    return f"{schema}://{netloc}/.tinysesam/start?rd={quote(rest, safe='')}"


def _gate_cookie(self, request, user, orig_url: str, roles_groups, session=None) -> Optional[str]:
    """The `Set-Cookie` value with a fresh gate token — or None.

    Only for a full SESSION of the same account, never for an API key: a machine holds
    no cookie, and a token from a key would live on in the browser after the key
    is revoked. Only for a protected host (`_gate_hosts`). The required roles
    are in the audience (`gate.audience`) so that a token from a check without
    roles does not apply at a path with roles."""
    if not self.cfg.gate_token_enabled:
        return None
    from urllib.parse import urlsplit
    from . import gate as _gate
    host = (urlsplit(orig_url or "").hostname or "").lower().rstrip(".")
    if not host or host not in self._gate_hosts():
        return None
    s = session if session is not None else self._session_from_request(request)
    if not s or not s["mfa_ok"] or s["user_id"] != user["id"]:
        return None
    # A service account has no session, so this is unreachable today; the bolt keeps it that way should one ever
    # come by: a gate token says `ts_auth=session`, and `service` with `session` is an error at every client.
    if user["is_service"]:
        return None
    # Every mandatory slot is in the token too, whatever `forward_headers` lists: `ts_kind` is always signed.
    fields = self._forward_header_map()
    values = self._forward_values(user, host)
    # The token stands for the session row checked above, whatever way the account dict came in (T-75): signed,
    # so the fast path at the proxy says `Remote-Auth: session` exactly like the way back through /auth/forward.
    values["auth"] = self._FORWARD_AUTH_KINDS["session"]
    claims = {slot: "".join(z for z in values[slot] if z >= " " and z != "\x7f") for slot in fields}
    ttl = int(self.cfg.gate_token_ttl_sec)
    # The wall clock, not `_manager._now()`: the proxy checks iat/nbf/exp against its own system clock,
    # and after a backward NTP step `_manager._now()` stays ahead for the process lifetime (B-7).
    token = _gate.issue(self._gate_key_name, iss=self.gate_issuer(),
                             aud=_gate.audience(host, roles_groups), sub=str(user["id"]),
                             claims=claims, ttl=ttl, now=_manager._wall_now())
    return _gate.set_cookie(self.cfg.gate_cookie_name, token, ttl)


def _forwarded_url(self, request: Request) -> str:
    """Reconstruct the original URL requested by the proxy (Caddy/Traefik: X-Forwarded-*,
    nginx: X-Original-URL). Fallback: Referer resp. '/'.

    **`X-Forwarded-Host` wins over `X-Original-URL`** (attack round B, F1). Caddy and Traefik set the
    `X-Forwarded-*` headers themselves and pass every other header of the browser through unchanged —
    `X-Original-URL` included. Until 0.25 an absolute `X-Original-URL` came first, so a browser that
    sent `X-Original-URL: https://dav.example.com/` to `web.example.com` had every per-application
    decision (app passwords, OAuth audience, approval per application, "signed out here only") taken
    for the wrong host. `X-Original-URL` now counts only where no `X-Forwarded-Host` is present
    (an nginx configuration that sets nothing else); where both are present and disagree,
    `_forwarded_conflict` refuses the request — either may be the forged one (an older nginx
    configuration passes the browser's `X-Forwarded-Host` through). `trusted_proxies` cannot tell the
    two apart: the peer of `/auth/forward` is always the proxy, and it forwards the browser's headers
    verbatim."""
    h = request.headers
    orig = (h.get("x-original-url") or "").strip()     # nginx auth_request
    absolute = "://" in orig
    host = (h.get("x-forwarded-host") or "").split(",")[0].strip()
    if absolute and not host:
        return orig
    proto = (h.get("x-forwarded-proto") or "https").split(",")[0].strip()
    host = host or (h.get("host") or "").split(",")[0].strip()
    # The path of an absolute X-Original-URL only when X-Forwarded-Uri is missing — and only after
    # `_forwarded_conflict` has found its host equal to X-Forwarded-Host.
    uri = (h.get("x-forwarded-uri") or (self._url_rest(orig) if absolute else orig)
           or h.get("x-original-uri") or "/")
    if host:
        return f"{proto}://{host}{uri}"
    return h.get("referer") or "/"


def _forwarded_conflict(self, request: Request) -> bool:
    """Do the proxy headers name two different targets? Then one of them came from the browser.

    True when an absolute `X-Original-URL` and `X-Forwarded-Host` are both present and differ in the host
    (port included, default ports dropped), in the scheme (if `X-Forwarded-Proto` is present) or in path
    and query (if `X-Forwarded-Uri` is present). The nginx templates set all four to the same request;
    Caddy and Traefik set no `X-Original-URL`, so there it can only be the browser's own. A malformed
    value counts as a conflict (fail closed)."""
    from urllib.parse import urlsplit
    h = request.headers
    orig = (h.get("x-original-url") or "").strip()
    fhost = (h.get("x-forwarded-host") or "").split(",")[0].strip()
    if "://" not in orig or not fhost:
        return False
    try:
        o = urlsplit(orig)
        f = urlsplit("//" + fhost)
        o_port, f_port = o.port, f.port
    except ValueError:
        return True
    scheme = (o.scheme or "").lower()
    proto = (h.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    if proto and proto != scheme:
        return True
    default = {"http": 80, "https": 443}.get(scheme)

    def name(parts, port):
        return ((parts.hostname or "").rstrip("."), None if port == default else port)

    if not o.hostname or name(o, o_port) != name(f, f_port):
        return True
    uri = h.get("x-forwarded-uri")
    return bool(uri) and uri != (self._url_rest(orig) or "/")


def _forward_app(self, url_or_host: str) -> dict:
    """The gate's settings for an application (T-21): `name`, `login`, `logout`, `app_passwords` (T-66) and `icon`
    (`apps[id].icon` of the application whose `hosts` name the host, T-104; None without one), from
    `forward_apps[host]` with `forward_login`/`forward_logout` as fallback. The host without port, lowercase."""
    from urllib.parse import urlsplit
    raw = str(url_or_host or "")
    host = ((urlsplit(raw).hostname if "://" in raw else raw.split(":", 1)[0]) or "").lower().rstrip(".")
    e = {}
    for h, values in (self.cfg.forward_apps or {}).items():
        if str(h).strip().lower().rstrip(".") == host:
            e = dict(values or {})
            break
    name: object = e.get("name")
    owner = self._app_of_host(host)
    icon = (self.cfg.apps or {}).get(owner, {}).get("icon") if owner else None
    if not name:
        # T-101: a host of `apps[id].hosts` without its own name in `forward_apps` takes the application's.
        label = (self.cfg.apps or {}).get(owner, {}).get("name") if owner else None
        name = (label.get(self.cfg.lang) or label.get("en") or next(iter(label.values()), "")
                if isinstance(label, dict) else label)
    return {"name": str(name or ""), "login": str(e.get("login") or self.cfg.forward_login),
            "logout": str(e.get("logout") or self.cfg.forward_logout),
            # T-66: only the literal True switches Basic auth on (config_check refuses anything else).
            "app_passwords": e.get("app_passwords") is True, "icon": icon if isinstance(icon, str) else None}


def _gate_host(self, request) -> str:
    """The protected host to which this request went (via the proxy: X-Forwarded-Host, otherwise
    Host) — or "" if this installation does not protect it. For the sign-out routes under
    `/.tinysesam/`: they act on the gate cookie of EXACTLY this host."""
    h = request.headers
    raw = (h.get("x-forwarded-host") or h.get("host") or "").split(",")[0].strip()
    host = raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw
    host = host.lower().rstrip(".")
    return host if host and host in self._gate_hosts() else ""


def _delete_gate_cookie(self, response) -> None:
    """Delete this host's gate cookie (attributes as when setting it, otherwise it does not apply)."""
    response.headers.append("set-cookie", f"{self.cfg.gate_cookie_name}=; Path=/; Max-Age=0; "
                                          "Secure; HttpOnly; SameSite=Lax")


def _forward_login_url(self, orig_url: str, request: Optional[Request] = None,
                       direct: bool = False) -> str:
    """Central login URL (on base_url resp. derived) with next=<orig_url>.

    Exception against a silent endless loop: **without `cookie_domain` the session cookie applies
    host-only.** If the login URL then points to a different host than the requested one,
    TinySesam sets the cookie on host A and sends the browser to host B, where it is not
    sent along — the proxy asks again, it goes to the login again, without an error message
    and without a log line. If the requested host is in `trusted_redirect_hosts`, we therefore build the
    login URL there: the same host on which the cookie applies.

    `base_url` remains unaffected — OIDC/SAML callbacks continue to need the one fixed
    address registered at the IdP. Only the own login page is affected.
    The real fix for SSO across several subdomains remains `cookie_domain=".example.com"`.

    The base comes from `public_base()`, i.e. from the same one rule as everywhere:
    `base_url` wins (the headers are then not even read), otherwise a
    derived host counts only from `trusted_redirect_hosts` or loopback, otherwise "" remains.
    **The one exception is the paragraph above** and it is deliberate: without `cookie_domain`
    the requested — co-trusted — host may claim the login page, otherwise the sign-in
    goes round in circles. `config_check` announces this case at startup.
    """
    from urllib.parse import quote, urlsplit
    candidate = ""
    if not self.cfg.base_url and request is not None:
        h = request.headers
        proto = (h.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
        host = (h.get("x-forwarded-host") or h.get("host") or request.url.netloc).split(",")[0].strip()
        # R4-01 applies here too: Host and X-Forwarded-Host come from the requester. If the
        # derived base does not withstand the check, the login URL stays relative — the
        # browser resolves it against the called host, so a foreign name does
        # not get into the redirect.
        candidate = f"{self._login_schema(proto, host)}://{host}" if host else ""
    base = self.public_base(candidate=candidate)
    if base and not self.cfg.cookie_domain:
        # Host from orig_url, not again from the headers: forwarded_url() has already evaluated
        # X-Original-URL and X-Forwarded-*. The whitelist trusted_redirect_hosts is
        # at the same time the protection — a forged X-Forwarded-Host cannot bend the login URL
        # to a foreign host.
        o = urlsplit(orig_url or "")
        if (o.scheme in ("http", "https") and o.hostname
                and o.hostname != (urlsplit(base).hostname or "")
                and o.hostname in {security.host_name(h) for h in (self.cfg.trusted_redirect_hosts or [])}):
            # Through the same form check as every other base (R5-1): `o.netloc` is raw and
            # carried a user part (`https://foreign.example@app.example.com`) unchanged
            # into the login URL; the scheme came unchecked from X-Forwarded-Proto/X-Original-URL.
            base = security.normalize_base(
                f"{self._login_schema(o.scheme, o.hostname)}://{o.netloc}") or base
    # Origin of the base + path of the login page WITH prefix (T-15): the base may already
    # carry the prefix (base_url) or not at all (derived, rebuilt for the requested host) —
    # `browser_path()` sets it from the one source, so only scheme and host count from the base.
    origin = ""
    if base:
        parts = urlsplit(str(base))
        origin = f"{parts.scheme}://{parts.netloc}"
    # `direct` (T-21, and every re-check at the provider, B-2): straight into the OIDC round instead of
    # onto the login page.
    path = "/auth/oidc/start" if direct else self.cfg.login_path
    destination = f"{origin}{self.browser_path(request, path)}?next={quote(orig_url or '/', safe='')}"
    # If this installation protects several applications, the target host belongs in the login URL:
    # only then does `/auth/oidc/start` know for which client it has to begin the round (T-14).
    # Without that every sign-in would run via the default client, and the approval that the
    # provider grants per client would be ineffective.
    application = self._oidc_application(orig_url)
    if application:
        destination += f"&app={quote(application, safe='')}"
    return destination


def _login_schema(self, schema: str, host: str) -> str:
    """The scheme of the login URL if it comes from the request (R5-1).

    Without `base_url` it comes from `X-Forwarded-Proto` resp. `X-Original-URL` — inputs that
    not only the proxy sets. With `cookie_secure=True`, `http` is never right there: the
    session cookie would not arrive at all over http, but the password would go in plaintext over the
    network. So https, except for loopback (local setup without a certificate)."""
    schema = (schema or "").strip().lower()
    if schema not in ("http", "https"):
        schema = "https"
    if schema == "http" and self.cfg.cookie_secure:
        from urllib.parse import urlsplit
        try:
            name = urlsplit("//" + (host or "")).hostname or ""
        except ValueError:
            name = ""
        if not security.own_host(name):      # without a list: only loopback counts
            schema = "https"
    return schema


# ---------- Approvals per application (T-14) ----------
def _oidc_application(self, url_or_host: str) -> str:
    """The client key for this address — "" if this installation protects only one
    application. The empty return value is intentional: it keeps every call site
    word-for-word at the behaviour of 0.18.0 as long as `oidc_clients` is empty."""
    from urllib.parse import urlsplit
    registry = getattr(self, "oidc_clients", None)
    if not registry or not registry.several:
        return ""
    raw = str(url_or_host or "")
    host = urlsplit(raw).hostname if "://" in raw else raw
    return registry.key_name_for_host(host or "")


def _record_oidc_approval(self, token: str, client: str, roles=None) -> None:
    """The provider has approved for this application — note it on the session."""
    self.store.put_oidc_grant(self.store.session_hash(token), client or "*",
                              _manager._now(), roles)


def _oidc_approval_valid(self, token_hash: str, client: str) -> tuple:
    """May this session enter this application? Return `(yes, reason)`.

    `reason` is "" for yes, otherwise "missing" (the provider has never approved
    for this application) or "stale" (the approval is older than `oidc_revalidate_minutes`).
    The difference matters: in the first case the person has never been here, in the second
    only the deadline expires — and the hop via the provider is then usually
    invisible because its session continues to exist.

    Without several clients the answer is always yes. An installation with one client
    thus behaves exactly like 0.18.0, even if `oidc_revalidate_minutes` is set:
    there is no per-application approval there that could expire.
    """
    registry = getattr(self, "oidc_clients", None)
    if not registry or not registry.several:
        return True, ""
    grant = self.store.get_oidc_grant(token_hash, client or "*")
    if not grant:
        return False, "missing"
    deadline = int(self.cfg.oidc_revalidate_minutes or 0) * 60
    if deadline and (_manager._now() - int(grant["checked_at"])) > deadline:
        return False, "stale"
    return True, ""
