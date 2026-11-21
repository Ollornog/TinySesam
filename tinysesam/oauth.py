"""OAuth 2.1 authorization server for human-operated tools — MCP clients such as Claude Code (T-36, ADR-11).

TinySesam stays the place where people sign in (chain, TOTP, passkey, link). This module adds the protocol on
top, with own small handlers and no protocol framework: discovery (RFC 8414), open dynamic client registration
(RFC 7591) for public loopback clients, the authorization code flow with PKCE S256 and a consent page,
the token endpoint (authorization_code, refresh_token with rotation and reuse detection), revocation
(RFC 7009) and the protected-resource metadata (RFC 9728) for the applications behind forward auth. The
applications themselves contain no OAuth code: `/auth/forward` accepts the access token and sets `Remote-*`
as for a session.

The rules and where they come from are in `backlog/ADR-11-oauth-authorization-server-in-tinysesam.md`. In short:

* **Tokens** are opaque, 256 random bits, `tsat_`/`tsrt_`/`tsac_` + Base62 + CRC32 (GitHub's format: secret
  scanners recognise them, a typo is rejected before the database). The database holds only an HMAC-SHA-256
  digest keyed with the pepper — the pepper is never in the database.
* **Codes** live 60 s, are consumed atomically and bound to client, redirect URI, PKCE challenge, resource,
  scope and account. A second exchange revokes everything the first one produced.
* **Refresh tokens** rotate on every use; a used one coming back revokes the whole family (grant).
* **Redirect URIs** are compared exactly — only the port of a loopback address is free (RFC 8252 §7.3).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import zlib
from typing import Any, Optional
from urllib.parse import urlencode, urlsplit

from fastapi import Request

from .store import now as _now

#: Environment variable with the pepper (Base64 of at least 32 random bytes; `_PREVIOUS`: older ones). Takes
#: precedence over `oauth_pepper_file`. Without both the pepper is a random key of its own in the database (ADR-12).
PEPPER_ENV = "TINYSESAM_OAUTH_PEPPER"

ACCESS_PREFIX = "tsat_"
REFRESH_PREFIX = "tsrt_"
CODE_PREFIX = "tsac_"

#: `mcp` = act for the account at the resource; `offline_access` = a refresh token comes along.
SCOPES = ("mcp", "offline_access")
DEFAULT_SCOPE = "mcp"

CODE_TTL_SEC = 60
REQUEST_TTL_SEC = 600
#: Open registration: per address and hour, and how many registrations without a grant may exist at all.
REGISTER_PER_IP_HOUR = 20
IDLE_CLIENTS_MAX = 1000
#: A registration that never led to a grant goes after a day (`gc()`); a revoked grant stays a week.
IDLE_CLIENT_SEC = 86400
REVOKED_KEEP_SEC = 7 * 86400
#: Token, revocation and authorization requests per address and minute.
REQUESTS_PER_IP_MINUTE = 60
#: Upper bounds for what a client registers itself (RFC 7591 §5: everything there is the client's claim).
MAX_REDIRECT_URIS = 5
MAX_URI_LEN = 512
MAX_NAME_LEN = 100
MAX_BODY = 16384
#: How often the "last seen" of a device is written by an access token at most (seconds).
TOUCH_SEC = 60

_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BODY_LEN = 43          # 62**43 > 2**256
_CRC_LEN = 6            # 62**6 > 2**32
_TOKEN_RE = re.compile(r"[0-9A-Za-z]+")
_VERIFIER_RE = re.compile(r"[A-Za-z0-9\-._~]{43,128}")
_CHALLENGE_RE = re.compile(r"[A-Za-z0-9\-_]{43}")
#: Loopback redirect URI of a native app (RFC 8252 §7.3): http, a loopback host, any port, a path — no user
#: info, no fragment, no backslash or white space. `localhost` is accepted on purpose (ADR-11: Claude Code
#: registers `http://localhost:<port>/callback`), against the recommendation of RFC 8252 §8.3.
_LOOPBACK_RE = re.compile(r"http://(localhost|127\.0\.0\.1|\[::1\])(?::(\d{1,5}))?(/[^\s#\\]*)?")
#: A forwarded path that the application might resolve differently than the comparison (dot segments, encoded
#: separators, backslash, NUL) is never covered by a token — the same rule as the share paths of the templates.
_UNSAFE_PATH = re.compile(r"(?i)(^|/)\.\.?(/|;|%3b|$)|[\\\x00]|%(2e|2f|5c|00)")


class OAuthError(Exception):
    """An OAuth error answer: `error` code (RFC 6749 §5.2 and friends), description, HTTP status."""

    def __init__(self, error: str, description: str = "", status: int = 400):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status

    def body(self) -> dict:
        d = {"error": self.error}
        if self.description:
            d["error_description"] = self.description
        return d


# ---------- token format ----------

def _b62(n: int, width: int) -> str:
    out = []
    for _ in range(width):
        n, r = divmod(n, 62)
        out.append(_B62[r])
    return "".join(reversed(out))


def new_token(prefix: str) -> str:
    """`prefix` + 256 random bits in Base62 + CRC32 of the two in Base62."""
    body = _b62(int.from_bytes(secrets.token_bytes(32), "big"), _BODY_LEN)
    return prefix + body + _b62(zlib.crc32((prefix + body).encode("ascii")), _CRC_LEN)


def shape_ok(token, prefix: str) -> bool:
    """Prefix, length, alphabet and checksum — no database access. A false here is never a valid token."""
    if not isinstance(token, str) or not token.startswith(prefix):
        return False
    rest = token[len(prefix):]
    if len(rest) != _BODY_LEN + _CRC_LEN or not _TOKEN_RE.fullmatch(rest):
        return False
    body, crc = rest[:_BODY_LEN], rest[_BODY_LEN:]
    return hmac.compare_digest(crc, _b62(zlib.crc32((prefix + body).encode("ascii")), _CRC_LEN))


def pkce_s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")


# ---------- redirect URIs and resources ----------

def loopback_uri(uri) -> Optional[tuple]:
    """(host, port, path_and_query) of a valid loopback redirect URI — or None."""
    if not isinstance(uri, str) or len(uri) > MAX_URI_LEN or any(ord(z) < 0x21 or ord(z) == 0x7f for z in uri):
        return None
    m = _LOOPBACK_RE.fullmatch(uri)
    if not m:
        return None
    port = m.group(2)
    if port is not None and not 0 < int(port) <= 65535:
        return None
    return m.group(1), port, m.group(3) or "/"


def redirect_registered(registered: list, given: str) -> bool:
    """Exact comparison with the registered URIs; for a loopback URI only the port may differ (RFC 8252 §7.3)."""
    if not isinstance(given, str) or not given:
        return False
    if given in registered:
        return True
    g = loopback_uri(given)
    if g is None:
        return False
    for r in registered:
        p = loopback_uri(r)
        if p is not None and p[0] == g[0] and p[2] == g[2]:
            return True
    return False


def normalize_resource(url) -> Optional[str]:
    """A resource identifier in one canonical form (RFC 8707 §2: absolute URI, no fragment) — or None.

    Scheme and host in lower case, default port dropped, no query, no trailing slash (the root stays empty)."""
    if not isinstance(url, str) or not url or len(url) > MAX_URI_LEN or any(ord(z) < 0x21 for z in url):
        return None
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return None
    if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password or p.fragment or p.query:
        return None
    host = p.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    if port and not ((p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80)):
        host = f"{host}:{port}"
    return f"{p.scheme}://{host}{p.path.rstrip('/')}"


def resource_covers(resource: str, url: str) -> bool:
    """Does a request to `url` fall under the resource? Same origin, and the path is the resource path or below."""
    try:
        u = urlsplit(url)
    except ValueError:
        return False
    if _UNSAFE_PATH.search(u.path or ""):
        return False
    base = normalize_resource(f"{u.scheme}://{u.netloc}")
    r = normalize_resource(resource)
    if base is None or r is None:
        return False
    path = u.path or "/"
    r_origin = r.split("/", 3)
    r_path = "/" + r_origin[3] if len(r_origin) > 3 else ""
    if base != "/".join(r_origin[:3]):
        return False
    return not r_path or path == r_path or path.startswith(r_path + "/")


def metadata_path(resource: str) -> str:
    """The path of the RFC 9728 document of a resource on its own host."""
    r = normalize_resource(resource) or ""
    parts = r.split("/", 3)
    return "/.well-known/oauth-protected-resource" + ("/" + parts[3] if len(parts) > 3 else "")


# ---------- pepper ----------

def derive_pepper(master_key: bytes) -> bytes:
    """The pepper up to 0.25.x: a subkey of the base key. Kept only so that an installation's existing connections
    stay valid after the update (a previous key of the pepper keyring, `keys.DERIVED_V1`)."""
    return hmac.new(master_key, b"tinysesam/oauth-token-pepper/v1", hashlib.sha256).digest()


# ---------- the server ----------

class OAuthServer:
    """The protocol logic. One instance per `TinySesam` (`auth._oauth`), built when `oauth_enabled` is on."""

    def __init__(self, auth, peppers):
        self.auth = auth
        self.store = auth.store
        #: The pepper keyring (`keys.Keyring`): the active pepper digests new tokens, the previous ones still
        #: find what they digested — until `tinysesam keys retire --purpose oauth-pepper`.
        self.peppers = peppers
        #: Services with `client_credentials` + `private_key_jwt` (T-60, ADR-13) — a `ServiceClients`, set by
        #: `TinySesam._oauth_server()` only with the switch on (this module does not import that one: no cycle).
        self.services: Any = None

    @property
    def pepper_origin(self) -> str:
        return self.peppers.origin

    # --- helpers ---
    def digest(self, token: str) -> str:
        return self._digest(self.peppers.active.material, token)

    @staticmethod
    def _digest(pepper: bytes, token: str) -> str:
        return hmac.new(pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def _find(self, token: str, lookup):
        """(digest, row) of a stored code or token — with the active pepper first, then the previous ones. A token
        issued before a pepper rotation is found by its old digest; the next refresh issues it anew."""
        for key in self.peppers.keys:
            h = self._digest(key.material, token)
            row = lookup(h)
            if row is not None:
                return h, row
        return self.digest(token), None

    @property
    def cfg(self):
        return self.auth.cfg

    def issuer(self) -> str:
        """`base_url` without a trailing slash — fixed, never from the request (RFC 8414 §2, RFC 9207)."""
        from . import security
        return (security.normalize_base(str(self.cfg.base_url or "").strip()) or "").rstrip("/")

    def endpoint(self, path: str) -> str:
        return self.issuer() + path

    def resources(self) -> list:
        return [r for r in (normalize_resource(x) for x in (self.cfg.oauth_resources or [])) if r]

    def resource_for(self, url: str) -> Optional[str]:
        """The configured resource a forwarded URL falls under — or None."""
        for r in self.resources():
            if resource_covers(r, url):
                return r
        return None

    def metadata(self) -> dict:
        """RFC 8414. Only what is built; no CIMD (`client_id_metadata_document_supported`) — it needs internet."""
        doc: dict = {
            "issuer": self.issuer(),
            "authorization_endpoint": self.endpoint("/auth/oauth/authorize"),
            "token_endpoint": self.endpoint("/auth/oauth/token"),
            "registration_endpoint": self.endpoint("/auth/oauth/register"),
            "revocation_endpoint": self.endpoint("/auth/oauth/revoke"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": list(SCOPES),
            "authorization_response_iss_parameter_supported": True,
        }
        if self.services is not None:
            doc["grant_types_supported"] = ["authorization_code", "refresh_token", "client_credentials"]
            doc["token_endpoint_auth_methods_supported"] = ["none", "private_key_jwt"]
            doc["token_endpoint_auth_signing_alg_values_supported"] = list(self.services.ALGORITHMS)
        return doc

    def resource_metadata(self, resource: str) -> dict:
        """RFC 9728 for one configured resource."""
        doc = {"resource": resource, "authorization_servers": [self.issuer()],
               "scopes_supported": list(SCOPES), "bearer_methods_supported": ["header"]}
        name = self.auth._forward_app(resource)["name"]
        if name:
            doc["resource_name"] = name
        return doc

    def challenge(self, resource: str, error: bool) -> str:
        """`WWW-Authenticate` of a 401 at a resource (RFC 9728 §5.1, RFC 6750 §3)."""
        r = normalize_resource(resource) or resource
        origin = "/".join(r.split("/", 3)[:3])
        value = f'Bearer resource_metadata="{origin}{metadata_path(r)}"'
        if error:
            value += ', error="invalid_token"'
        return value

    def _scope(self, raw, allowed=SCOPES) -> list:
        parts = [p for p in str(raw or "").split(" ") if p]
        if not parts:
            return [DEFAULT_SCOPE]
        if any(p not in allowed for p in parts) or len(parts) != len(set(parts)):
            raise OAuthError("invalid_scope", "unknown or repeated scope")
        if DEFAULT_SCOPE not in parts:
            parts.insert(0, DEFAULT_SCOPE)
        return parts

    def _audit(self, event: str, username=None, ip=None, detail=None) -> None:
        self.auth.audit(event, username, ip, detail)

    # --- registration (RFC 7591) ---
    def register(self, meta, ip) -> dict:
        """Open registration of a public loopback client. Everything the client claims is a claim (RFC 7591 §5):
        no URL it names is fetched, the name is shown as unverified."""
        if not isinstance(meta, dict):
            raise OAuthError("invalid_client_metadata", "a JSON object is expected")
        uris = meta.get("redirect_uris")
        if not isinstance(uris, list) or not uris or len(uris) > MAX_REDIRECT_URIS:
            raise OAuthError("invalid_redirect_uri", f"1 to {MAX_REDIRECT_URIS} redirect_uris are required")
        for u in uris:
            if loopback_uri(u) is None:
                raise OAuthError("invalid_redirect_uri",
                                 "only loopback redirect URIs (http://localhost, 127.0.0.1 or [::1]) are accepted")
        method = meta.get("token_endpoint_auth_method", "none")
        if method != "none":
            raise OAuthError("invalid_client_metadata", "only public clients (token_endpoint_auth_method=none)")
        grants = meta.get("grant_types", ["authorization_code", "refresh_token"])
        if (not isinstance(grants, list) or not grants
                or any(g not in ("authorization_code", "refresh_token") for g in grants)
                or "authorization_code" not in grants):
            raise OAuthError("invalid_client_metadata", "grant_types: authorization_code and refresh_token only")
        responses = meta.get("response_types", ["code"])
        if not isinstance(responses, list) or responses != ["code"]:
            raise OAuthError("invalid_client_metadata", "response_types: code only")
        if "scope" in meta and meta["scope"] is not None:
            self._scope(meta["scope"])
        name = meta.get("client_name")
        if name is not None and not isinstance(name, str):
            raise OAuthError("invalid_client_metadata", "client_name must be a string")
        name = "".join(z for z in (name or "") if z >= " " and z != "\x7f" and not 0x202a <= ord(z) <= 0x202e
                       and not 0x2066 <= ord(z) <= 0x2069).strip()[:MAX_NAME_LEN] or "unnamed client"
        if not self.auth.rl.allow(("oauth_register", ip or "?"), REGISTER_PER_IP_HOUR, 3600):
            raise OAuthError("temporarily_unavailable", "too many registrations from this address", 429)
        if self.store.oauth_count_idle_clients() >= IDLE_CLIENTS_MAX:
            raise OAuthError("temporarily_unavailable", "too many open registrations", 429)
        client_id = "tsc_" + secrets.token_urlsafe(18)
        now = _now()
        self.store.oauth_add_client(client_id, name, uris, now, ip)
        self._audit("oauth_client_registered", None, ip, f"client={client_id} name={_detail(name)}")
        # Only fields with a value: Claude Code (MCP TypeScript SDK) rejects null or "" where a URL or list is
        # expected (measured with Ory Hydra's answer in the spike).
        return {"client_id": client_id, "client_id_issued_at": now, "client_name": name, "redirect_uris": uris,
                "grant_types": grants, "response_types": ["code"], "token_endpoint_auth_method": "none",
                "scope": " ".join(SCOPES)}

    # --- authorization request ---
    def check_authorize(self, q: dict) -> tuple[dict, dict]:
        """Validate the request (RFC 6749 §4.1.1, RFC 7636, RFC 8707). Returns (client, params).

        Raises `OAuthError` with `redirect=False` while client and redirect URI are not established — then the
        error must NOT go to the redirect URI (RFC 6749 §4.1.2.1) — and with `redirect=True` afterwards."""
        client = self.store.oauth_client(q.get("client_id"))
        if client is None or self.store.oauth_service(client["client_id"]) is not None:
            # A service (T-60) has no person and no redirect URI: it never starts an authorization.
            err = OAuthError("invalid_client", "unknown client_id")
            err.redirect = False   # type: ignore[attr-defined]
            raise err
        redirect_uri = q.get("redirect_uri") or ""
        if not redirect_registered(client["redirect_uris"], redirect_uri):
            err = OAuthError("invalid_request", "redirect_uri is missing or not registered for this client")
            err.redirect = False   # type: ignore[attr-defined]
            raise err

        def fail(error, description):
            e = OAuthError(error, description)
            e.redirect = True      # type: ignore[attr-defined]
            e.redirect_uri = redirect_uri   # type: ignore[attr-defined]
            e.state = q.get("state")        # type: ignore[attr-defined]
            return e

        if q.get("response_type") != "code":
            raise fail("unsupported_response_type", "response_type must be code")
        if q.get("code_challenge_method") != "S256":
            raise fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
        challenge = q.get("code_challenge") or ""
        if not _CHALLENGE_RE.fullmatch(challenge):
            raise fail("invalid_request", "code_challenge must be a Base64url SHA-256 (43 characters)")
        try:
            scope = self._scope(q.get("scope"))
        except OAuthError as e:
            raise fail(e.error, e.description) from None
        resources = q.get("_resources") or []
        if len(resources) != 1:
            raise fail("invalid_target", "exactly one resource parameter is required")
        resource = normalize_resource(resources[0])
        if resource is None or resource not in self.resources():
            raise fail("invalid_target", "unknown resource")
        state = q.get("state")
        if state is not None and len(state) > 1024:
            raise fail("invalid_request", "state is too long")
        return client, {"redirect_uri": redirect_uri, "state": state, "code_challenge": challenge,
                        "scope": " ".join(scope), "resource": resource}

    def begin(self, client: dict, params: dict) -> tuple[str, str]:
        """Store the request; returns (request id, browser secret) — the secret goes into a flow cookie."""
        rid, browser = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        self.store.oauth_add_request(self.digest(rid), self.digest(browser), client["client_id"], params,
                                     _now() + REQUEST_TTL_SEC)
        return rid, browser

    def pending(self, rid: str, browser: str) -> Optional[dict]:
        """The stored request — only for the browser that started it, only within its lifetime."""
        if not rid or not browser:
            return None
        req = self.store.oauth_request(self.digest(rid), _now())
        if req is None or not hmac.compare_digest(req["browser_hash"], self.digest(browser)):
            return None
        req["client"] = self.store.oauth_client(req["client_id"])
        return req if req["client"] else None

    def redirect_url(self, redirect_uri: str, **values) -> str:
        """The answer to the client: its redirect URI plus the values, `iss` always (RFC 9207)."""
        values = {k: v for k, v in values.items() if v is not None}
        values["iss"] = self.issuer()
        return redirect_uri + ("&" if "?" in redirect_uri else "?") + urlencode(values)

    def decide(self, rid: str, req: dict, user: dict, allow: bool, ip) -> str:
        """Consent answered: single use; returns the URL the browser is sent to."""
        if not self.store.oauth_take_request(self.digest(rid)):
            raise OAuthError("invalid_request", "this request was already answered", 400)
        p = req["params"]
        client = req["client"]
        if not allow:
            self._audit("oauth_consent", user["username"], ip, f"client={client['client_id']} decision=deny")
            return self.redirect_url(p["redirect_uri"], error="access_denied", state=p.get("state"))
        code = new_token(CODE_PREFIX)
        now = _now()
        self.store.oauth_add_code(self.digest(code), client["client_id"], int(user["id"]), p["redirect_uri"],
                                  p["code_challenge"], p["resource"], p["scope"], now, now + CODE_TTL_SEC)
        self.store.oauth_touch_client(client["client_id"], now)
        self._audit("oauth_consent", user["username"], ip,
                    f"client={client['client_id']} decision=allow resource={_detail(p['resource'])} "
                    f"scope={_detail(p['scope'])}")
        return self.redirect_url(p["redirect_uri"], code=code, state=p.get("state"))

    # --- token endpoint ---
    def _client_of_request(self, form: dict) -> dict:
        if form.get("client_secret") or form.get("client_assertion"):
            raise OAuthError("invalid_client", "public clients only — no client secret", 401)
        client = self.store.oauth_client(form.get("client_id"))
        if client is None or self.store.oauth_service(client["client_id"]) is not None:
            raise OAuthError("invalid_client", "unknown client_id", 401)
        return client

    def token(self, form: dict, ip) -> dict:
        grant_type = form.get("grant_type")
        if grant_type == "client_credentials" and self.services is not None:
            return self.services.token(form, ip)
        if grant_type not in ("authorization_code", "refresh_token"):
            raise OAuthError("unsupported_grant_type", "authorization_code or refresh_token"
                             + (" or client_credentials" if self.services is not None else ""))
        client = self._client_of_request(form)
        if grant_type == "authorization_code":
            return self._exchange_code(client, form, ip)
        return self._refresh(client, form, ip)

    def _lifetimes(self) -> tuple[int, int, Optional[int]]:
        c = self.cfg
        return (int(c.oauth_access_token_ttl_sec), int(c.oauth_refresh_idle_days) * 86400,
                int(c.oauth_refresh_max_days) * 86400 or None)

    def _pair(self, scope: str, with_refresh: bool) -> tuple[str, Optional[str], list]:
        access_ttl, idle, _ = self._lifetimes()
        now = _now()
        at = new_token(ACCESS_PREFIX)
        rows = [(self.digest(at), "access", scope, now + access_ttl)]
        rt = None
        if with_refresh:
            rt = new_token(REFRESH_PREFIX)
            rows.append((self.digest(rt), "refresh", scope, now + idle))
        return at, rt, rows

    def _answer(self, at: str, rt: Optional[str], scope: str) -> dict:
        out = {"access_token": at, "token_type": "Bearer", "expires_in": self._lifetimes()[0], "scope": scope}
        if rt:
            out["refresh_token"] = rt
        return out

    def _exchange_code(self, client: dict, form: dict, ip) -> dict:
        code = form.get("code") or ""
        if not shape_ok(code, CODE_PREFIX):
            raise OAuthError("invalid_grant", "invalid authorization code")
        h, row = self._find(code, self.store.oauth_code)
        if row is None:
            raise OAuthError("invalid_grant", "invalid authorization code")
        # Reuse first, before any other field (RFC 6749 §4.1.2, RFC 9700 §4.2.4): a code that comes back was
        # seen by someone else — everything it produced is revoked.
        if row["consumed_at"] is not None or not self.store.oauth_consume_code(h, _now()):
            self._code_reused(row, ip)
            raise OAuthError("invalid_grant", "authorization code already used")
        now = _now()
        if row["expires_at"] <= now:
            raise OAuthError("invalid_grant", "authorization code expired")
        if row["client_id"] != client["client_id"]:
            raise OAuthError("invalid_grant", "authorization code was issued to another client")
        if form.get("redirect_uri") != row["redirect_uri"]:
            raise OAuthError("invalid_grant", "redirect_uri does not match the authorization request")
        verifier = form.get("code_verifier")
        # Downgrade in both directions (RFC 9700 §2.1.1): no verifier for a code with a challenge, or a verifier
        # for one without — both fail, and the code is gone either way (consumed above).
        if not verifier or not row["code_challenge"]:
            raise OAuthError("invalid_grant", "PKCE code_verifier is required")
        if not _VERIFIER_RE.fullmatch(verifier) or not hmac.compare_digest(pkce_s256(verifier),
                                                                           row["code_challenge"]):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        if form.get("resource") and normalize_resource(form["resource"]) != row["resource"]:
            raise OAuthError("invalid_target", "resource does not match the authorization request")
        if row["resource"] not in self.resources():
            raise OAuthError("invalid_target", "the resource is no longer configured")
        u = self.store.get_user(row["user_id"])
        if u is None or u["disabled"] or u["is_service"]:
            raise OAuthError("invalid_grant", "the account is not active")
        scope = row["scope"]
        at, rt, rows = self._pair(scope, "offline_access" in scope.split())
        _, _, max_age = self._lifetimes()
        grant_id = self.store.oauth_create_grant(h, client["client_id"], int(row["user_id"]), row["resource"],
                                                 scope, now, ip, now + max_age if max_age else None, rows)
        self._audit("oauth_token", u["username"], ip,
                    f"client={client['client_id']} grant={grant_id} refresh={'yes' if rt else 'no'}")
        self.auth._security_event("oauth_device_connected", u["id"], grant_id=grant_id, client_id=client["client_id"],
                    client_name=client["name"], resource=row["resource"])
        return self._answer(at, rt, scope)

    def _code_reused(self, row, ip) -> None:
        name = self.auth._account_name(row["user_id"])
        grant_id = row["grant_id"]
        self._audit("oauth_code_reuse", name, ip, f"client={row['client_id']} grant={grant_id or '-'}")
        if grant_id and self.store.oauth_revoke_grant(int(grant_id), "code_reuse", _now()):
            self._audit("oauth_revoked", name, ip, f"grant={grant_id} reason=code_reuse")
            self.auth._security_event("oauth_token_reuse", row["user_id"], grant_id=int(grant_id), client_id=row["client_id"],
                        kind="code")

    def _refresh(self, client: dict, form: dict, ip) -> dict:
        token = form.get("refresh_token") or ""
        if not shape_ok(token, REFRESH_PREFIX):
            raise OAuthError("invalid_grant", "invalid refresh token")
        h, row = self._find(token, self.store.oauth_token)
        if row is None or row["kind"] != "refresh":
            raise OAuthError("invalid_grant", "invalid refresh token")
        if row["g_client_id"] != client["client_id"]:
            raise OAuthError("invalid_grant", "refresh token was issued to another client")
        if row["g_revoked_at"] is not None:
            raise OAuthError("invalid_grant", "the grant was revoked")
        now = _now()
        if row["used_at"] is not None:
            same = self._grace_successor(row, now)
            if same is not None:
                return same
            self._refresh_reused(row, ip)
            raise OAuthError("invalid_grant", "refresh token already used")
        if row["expires_at"] <= now or (row["g_expires_at"] and row["g_expires_at"] <= now):
            raise OAuthError("invalid_grant", "refresh token expired")
        if form.get("resource") and normalize_resource(form["resource"]) != row["g_resource"]:
            raise OAuthError("invalid_target", "resource does not match the grant")
        grant_id = int(row["grant_id"])
        u = self.store.get_user(row["g_user_id"])
        if u is None or u["disabled"]:
            self.revoke_grant(grant_id, "account_disabled", ip)
            raise OAuthError("invalid_grant", "the account is not active")
        if row["g_resource"] not in self.resources():
            raise OAuthError("invalid_target", "the resource is no longer configured")
        # A refresh may narrow the scope of the new access token, never widen it (RFC 6749 §6); the refresh
        # token keeps the grant's scope.
        grant_scope = row["scope"].split()
        access_scope = grant_scope
        if form.get("scope"):
            access_scope = self._scope(form["scope"], allowed=tuple(grant_scope))
        at, rt, rows = self._pair(row["scope"], True)
        rows[0] = (rows[0][0], "access", " ".join(access_scope), rows[0][3])
        answer = self._answer(at, rt, " ".join(access_scope))
        grace = int(self.cfg.oauth_refresh_grace_sec or 0)
        successor = self.store.seal_oauth_successor(h, json.dumps(answer)) if grace > 0 else None
        if not self.store.oauth_rotate(h, grant_id, now, ip, rows, successor):
            # Another request rotated the same token in between — that one is the use, this one is a reuse.
            again = self.store.oauth_token(h)
            same = self._grace_successor(again, _now()) if again is not None else None
            if same is not None:
                return same
            self._refresh_reused(row, ip)
            raise OAuthError("invalid_grant", "refresh token already used")
        self._audit("oauth_refresh", u["username"], ip, f"client={client['client_id']} grant={grant_id}")
        return answer

    def _grace_successor(self, row, now: int) -> Optional[dict]:
        """Within the grace window the immediate predecessor gets the SAME successor back (Auth0/Okta pattern) —
        two processes of one client that refresh at once must not revoke each other. Only if the successor is
        still the family's current refresh token."""
        grace = int(self.cfg.oauth_refresh_grace_sec or 0)
        if grace <= 0 or not row["successor"] or row["used_at"] is None or now - int(row["used_at"]) > grace:
            return None
        try:
            answer = json.loads(self.store.open_oauth_successor(row) or "{}")
        except Exception:
            return None
        _, nxt = self._find(str(answer.get("refresh_token") or ""), self.store.oauth_token)
        if nxt is None or nxt["used_at"] is not None or nxt["g_revoked_at"] is not None:
            return None
        return answer

    def _refresh_reused(self, row, ip) -> None:
        grant_id = int(row["grant_id"])
        name = self.auth._account_name(row["g_user_id"])
        self._audit("oauth_refresh_reuse", name, ip, f"client={row['g_client_id']} grant={grant_id}")
        if self.store.oauth_revoke_grant(grant_id, "refresh_reuse", _now()):
            self._audit("oauth_revoked", name, ip, f"grant={grant_id} reason=refresh_reuse")
            self.auth._security_event("oauth_token_reuse", row["g_user_id"], grant_id=grant_id, client_id=row["g_client_id"],
                        kind="refresh")

    # --- revocation ---
    def revoke_request(self, form: dict, ip) -> None:
        """RFC 7009 for public clients: the token's family ends if it belongs to the client named. An unknown
        token or a foreign one is answered the same way (200) — the answer reveals nothing."""
        client = self._client_of_request(form)
        token = form.get("token") or ""
        if not (shape_ok(token, ACCESS_PREFIX) or shape_ok(token, REFRESH_PREFIX)):
            return
        _, row = self._find(token, self.store.oauth_token)
        if row is None or row["g_client_id"] != client["client_id"]:
            return
        self.revoke_grant(int(row["grant_id"]), "client", ip)

    def revoke_grant(self, grant_id: int, reason: str, ip=None) -> bool:
        g = self.store.oauth_grant(grant_id)
        if g is None or not self.store.oauth_revoke_grant(int(grant_id), reason, _now()):
            return False
        name = self.auth._account_name(g["user_id"])
        self._audit("oauth_revoked", name, ip, f"grant={grant_id} client={g['client_id']} reason={reason}")
        self.auth._security_event("oauth_device_revoked", g["user_id"], grant_id=int(grant_id), client_id=g["client_id"],
                    reason=reason)
        return True

    def revoke_user(self, user_id: int, reason: str) -> int:
        """Every connected device and, with the switch on, every service (T-60) of the account (with the switch off
        `TinySesam._services_revoked` takes what is left)."""
        n = self.services.revoke_user(user_id, reason) if self.services is not None else 0
        return n + sum(1 for gid in self.store.oauth_user_grant_ids(user_id) if self.revoke_grant(gid, reason))

    # --- resource side ---
    def user_for(self, token: str, url: str, ip) -> tuple[Optional[dict], str]:
        """(account, reason) for an access token at the forwarded URL. The account is checked on every request:
        a lock, a revoked grant or a removed resource takes effect at once."""
        if not shape_ok(token, ACCESS_PREFIX):
            return None, "malformed"
        _, row = self._find(token, self.store.oauth_token)
        now = _now()
        if row is None or row["kind"] != "access":
            return None, "unknown"
        service = row["s_client_id"] is not None
        if row["g_revoked_at"] is not None or (service and row["s_revoked_at"] is not None):
            return None, "revoked"
        if service and self.services is None:
            return None, "revoked"          # the switch is off: no service token counts any more
        if row["expires_at"] <= now or (row["g_expires_at"] and row["g_expires_at"] <= now):
            return None, "expired"
        if row["g_resource"] not in self.resources() or not resource_covers(row["g_resource"], url):
            return None, "audience"
        if service and row["g_resource"] not in json.loads(row["s_resources"] or "[]"):
            return None, "audience"
        u = self.store.get_user(row["g_user_id"])
        # A service account has no person and never consents — only a service (T-60) acts as one.
        if u is None or u["disabled"] or (u["is_service"] and not service):
            return None, "account_locked"
        if "mcp" not in row["scope"].split():
            return None, "scope"
        if row["created_at"] < now - TOUCH_SEC:
            g = self.store.oauth_grant(row["grant_id"])
            if g is not None and (g["last_used"] or 0) < now - TOUCH_SEC:
                self.store.oauth_touch_grant(int(row["grant_id"]), now, ip)
        d = dict(self.auth._as_dict(u) or {})
        d["_via"] = "oauth"
        d["_oauth_client"] = row["g_client_id"]
        d["_oauth_grant"] = int(row["grant_id"])
        # Like an automation key (R6-5): a token acts for the account at one resource — never as its admin.
        d["is_admin"] = 0
        if service:
            d["_oauth_service"] = True
            if row["s_roles"]:
                # The scope narrows, never widens — read against the account's roles on every request.
                d["roles"] = json.dumps(sorted(set(json.loads(row["s_roles"])) & set(self.auth.user_roles(u))))
        return d, ""

    # --- devices ---
    def devices(self, user_id=None) -> list:
        out = []
        for g in self.store.oauth_grants(_now(), user_id=user_id):
            out.append({"id": int(g["id"]), "client_id": g["client_id"], "client_name": g["client_name"] or "",
                        "user_id": int(g["user_id"]), "username": g["username"], "resource": g["resource"],
                        "scope": g["scope"], "created_at": g["created_at"], "last_used": g["last_used"],
                        "last_ip": g["last_ip"] or g["created_ip"] or ""})
        return out

    def gc(self) -> dict:
        return self.store.gc_oauth(_now(), IDLE_CLIENT_SEC, REVOKED_KEEP_SEC)


def _detail(value) -> str:
    """A value for an audit detail: no spaces or control characters (the detail is `key=value` pairs)."""
    return "".join(z if z > " " and z != "\x7f" else "_" for z in str(value or ""))[:200] or "-"


# ---------- routes ----------

def _consent_csp(policy: str, redirect_uri: str) -> str:
    """The consent page may not be framed (clickjacking: ASVS V10.7, `frame-ancestors 'none'`), and its form
    leads — after the POST, via a redirect that Chrome checks against `form-action` — to the client's loopback
    address, which must therefore be named."""
    p = urlsplit(redirect_uri)
    origin = f"{p.scheme}://{p.netloc}"
    parts = [d.strip() for d in (policy or "").split(";") if d.strip()]
    out, seen_frame = [], False
    for d in parts:
        name = d.split(None, 1)[0].lower()
        if name == "frame-ancestors":
            out.append("frame-ancestors 'none'")
            seen_frame = True
        elif name == "form-action":
            out.append(f"{d} {origin}")
        else:
            out.append(d)
    if not seen_frame:
        out.append("frame-ancestors 'none'")
    return "; ".join(out)


async def _read_body(request) -> bytes:
    """The body, at most `MAX_BODY` bytes — an open endpoint must not read whatever it is sent."""
    length = request.headers.get("content-length")
    if length and (not length.isdigit() or int(length) > MAX_BODY):
        raise OAuthError("invalid_request", "request body too large", 413)
    data = b""
    async for chunk in request.stream():
        data += chunk
        if len(data) > MAX_BODY:
            raise OAuthError("invalid_request", "request body too large", 413)
    return data


async def _form(request) -> dict:
    """application/x-www-form-urlencoded (RFC 6749 §3.2); a parameter twice is an error."""
    from urllib.parse import parse_qsl
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype != "application/x-www-form-urlencoded":
        raise OAuthError("invalid_request", "the body must be application/x-www-form-urlencoded")
    try:
        pairs = parse_qsl((await _read_body(request)).decode("utf-8"), keep_blank_values=True,
                          strict_parsing=False, max_num_fields=32)
    except (UnicodeDecodeError, ValueError):
        raise OAuthError("invalid_request", "the body cannot be read") from None
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise OAuthError("invalid_request", f"parameter {k} given more than once")
        out[k] = v
    return out


def add_routes(auth, r) -> None:
    """The OAuth routes on TinySesam's router (only with `oauth_enabled`)."""
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse, RedirectResponse, Response
    from . import security
    from .errors import ConfigError

    cfg = auth.cfg
    srv = auth._oauth_server()
    FLOW = "tinysesam_oauth"

    def error_json(e: OAuthError) -> JSONResponse:
        headers = {"Pragma": "no-cache"}
        if e.status == 401:
            headers["WWW-Authenticate"] = 'Basic realm="TinySesam"'
        if e.status == 429:
            headers["Retry-After"] = "60"
        return JSONResponse(e.body(), status_code=e.status, headers=headers)

    def limited(request: Request, bucket: str) -> Optional[str]:
        ip = auth.client_ip(request)
        if not auth.rl.allow((bucket, ip or "?"), REQUESTS_PER_IP_MINUTE, 60):
            auth._rejected(None, ip, bucket + "_ratelimit", login=False)
            return None
        return ip or ""

    def page_error(request: Request, status: int, message: str):
        return auth.render_page("error", status=status, request=request, code=status, message=message)

    # --- discovery ---
    @r.get("/.well-known/oauth-authorization-server")
    @r.get("/.well-known/oauth-authorization-server/{rest:path}")
    def as_metadata(request: Request):
        return JSONResponse(srv.metadata(), headers={"Cache-Control": "max-age=300"})


    @r.get("/.well-known/oauth-protected-resource")
    @r.get("/.well-known/oauth-protected-resource/{rest:path}")
    def pr_metadata(request: Request, rest: str = ""):
        # The document lies on the APPLICATION's host (the proxy passes the path to TinySesam): the resource is
        # rebuilt from that host and the path behind the well-known prefix.
        h = request.headers
        proto = (h.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip().lower()
        host = (h.get("x-forwarded-host") or h.get("host") or "").split(",")[0].strip()
        wanted = normalize_resource(f"{proto}://{host}/{rest}") if host else None
        if wanted is None or wanted not in srv.resources():
            return JSONResponse({"error": "not_found"}, status_code=404)
        return JSONResponse(srv.resource_metadata(wanted), headers={"Cache-Control": "max-age=300"})


    # --- registration ---
    @r.post("/auth/oauth/register")
    async def register(request: Request):
        ip = auth.client_ip(request)
        try:
            ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                raise OAuthError("invalid_client_metadata", "the body must be application/json")
            try:
                meta = json.loads((await _read_body(request)).decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise OAuthError("invalid_client_metadata", "the body is no JSON") from None
            out = srv.register(meta, ip)
        except OAuthError as e:
            return error_json(e)
        return JSONResponse(out, status_code=201, headers={"Pragma": "no-cache"})


    # --- authorization ---
    @r.get("/auth/oauth/authorize")
    def authorize(request: Request):
        ip = limited(request, "oauth_authorize")
        if ip is None:
            return page_error(request, 429, auth.t("oauth.too_many"))
        q: dict = {}
        resources = []
        for k, v in request.query_params.multi_items():
            if k == "resource":
                resources.append(v)
            elif k in q:
                return page_error(request, 400, auth.t("oauth.invalid_request", reason=f"{k} twice"))
            else:
                q[k] = v
        q["_resources"] = resources
        try:
            client, params = srv.check_authorize(q)
        except OAuthError as e:
            if not getattr(e, "redirect", False):
                # Unknown client or redirect URI: never redirect there (RFC 6749 §4.1.2.1).
                auth.audit("oauth_authorize_denied", None, ip, f"error={e.error}")
                return page_error(request, 400, auth.t("oauth.invalid_request", reason=e.description))
            auth.audit("oauth_authorize_denied", None, ip,
                       f"client={_detail(q.get('client_id'))} error={e.error}")
            return RedirectResponse(srv.redirect_url(e.redirect_uri, error=e.error,  # type: ignore[attr-defined]
                                                     error_description=e.description,
                                                     state=e.state), 303)  # type: ignore[attr-defined]
        rid, browser = srv.begin(client, params)
        auth.audit("oauth_authorize", None, ip,
                   f"client={client['client_id']} resource={_detail(params['resource'])}")
        resp = RedirectResponse(auth.browser_path(request, "/auth/oauth/consent") + "?txn=" + rid, 303)
        auth._set_flow_cookie(resp, FLOW, browser, REQUEST_TTL_SEC)
        return resp


    def _req(request: Request, txn: str):
        return srv.pending(txn, request.cookies.get(auth.flow_cookie_name(FLOW)) or "")

    @r.get("/auth/oauth/consent")
    def consent_page(request: Request, txn: str = ""):
        req = _req(request, txn)
        if req is None:
            return page_error(request, 400, auth.t("oauth.expired"))
        user = auth.session_user(request)        # a full session — never an API key, never a half sign-in
        if not user:
            nxt = auth.browser_path(request, "/auth/oauth/consent") + "?txn=" + txn
            from urllib.parse import quote
            return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={quote(nxt, safe='')}", 303)
        # B-12: allowing a program is a new, lasting way in (a refresh token lives for days) — the same
        # freshness as a new passkey or API key. A stale session confirms first and comes back here.
        target = auth._reauth_target(request, auth.browser_path(request, "/auth/oauth/consent") + "?txn=" + txn)
        if target:
            return RedirectResponse(target, 303)
        if auth._fresh_enough(request, user) == "relogin":
            return page_error(request, 403, auth.t("api.stepup_relogin"))
        p = req["params"]
        host, port, _ = loopback_uri(p["redirect_uri"]) or ("?", None, "")
        access_ttl, idle, max_age = srv._lifetimes()
        resp = auth.render_page(
            "oauth_consent", request=request, user=user, txn=txn,
            client_name=req["client"]["name"], client_id=req["client"]["client_id"],
            redirect_host=host + (f":{port}" if port else ""), resource=p["resource"],
            resource_name=auth._forward_app(p["resource"])["name"], scope=p["scope"].split(),
            offline="offline_access" in p["scope"].split(), access_minutes=access_ttl // 60,
            idle_days=idle // 86400, max_days=(max_age or 0) // 86400)
        resp.headers["Content-Security-Policy"] = _consent_csp(resp.headers.get("content-security-policy", ""),
                                                               p["redirect_uri"])
        resp.headers["X-Frame-Options"] = "DENY"
        return resp


    @r.post("/auth/oauth/consent")
    async def consent_answer(request: Request):
        form = await request.form()
        auth.require_csrf(request, form.get("_csrf"))
        txn = str(form.get("txn") or "")
        req = _req(request, txn)
        user = auth.session_user(request)
        if req is None or user is None:
            return page_error(request, 400, auth.t("oauth.expired"))
        decision = str(form.get("decision") or "")
        if decision not in ("allow", "deny"):
            return page_error(request, 400, auth.t("oauth.invalid_request", reason="decision"))
        if decision == "allow" and auth._fresh_enough(request, user) is not None:
            # B-12: the page was fresh, the answer came too late. The request stays open (nothing was
            # decided): confirm, then the consent page again.
            target = auth._reauth_target(request, auth.browser_path(request, "/auth/oauth/consent") + "?txn=" + txn)
            if target:
                return RedirectResponse(target, 303)
            return page_error(request, 403, auth.t("api.stepup_relogin"))
        try:
            url = srv.decide(txn, req, user, decision == "allow", auth.client_ip(request))
        except OAuthError:
            return page_error(request, 400, auth.t("oauth.expired"))
        resp = RedirectResponse(url, 303)
        auth._delete_flow_cookie(resp, FLOW)
        return resp


    # --- token and revocation ---
    @r.post("/auth/oauth/token")
    async def token(request: Request):
        ip = limited(request, "oauth_token")
        if ip is None:
            return error_json(OAuthError("temporarily_unavailable", "too many requests", 429))
        try:
            if request.headers.get("authorization"):
                raise OAuthError("invalid_client", "public clients only — no client authentication", 401)
            out = srv.token(await _form(request), ip)
        except OAuthError as e:
            security.seclog.info("oauth token refused ip=%s error=%s", security.for_log(ip), e.error)
            return error_json(e)
        return JSONResponse(out, headers={"Pragma": "no-cache"})


    @r.post("/auth/oauth/revoke")
    async def revoke(request: Request):
        ip = limited(request, "oauth_revoke")
        if ip is None:
            return error_json(OAuthError("temporarily_unavailable", "too many requests", 429))
        try:
            srv.revoke_request(await _form(request), ip)
        except OAuthError as e:
            return error_json(e)
        return Response(status_code=200)


    # --- services (T-60, ADR-13) ---
    if srv.services is not None:
        services = srv.services

        @r.post("/auth/oauth/pair")
        async def service_pair(request: Request):
            ip = auth.client_ip(request)
            try:
                ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
                if ctype != "application/json":
                    raise OAuthError("invalid_request", "the body must be application/json")
                try:
                    body = json.loads((await _read_body(request)).decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    raise OAuthError("invalid_request", "the body is no JSON") from None
                out = services.pair(body, ip)
            except OAuthError as e:
                return error_json(e)
            return JSONResponse(out, status_code=201, headers={"Pragma": "no-cache", "Cache-Control": "no-store"})


        @r.post("/auth/oauth/service/keys")
        async def service_key(request: Request):
            ip = limited(request, "oauth_token")
            if ip is None:
                return error_json(OAuthError("temporarily_unavailable", "too many requests", 429))
            try:
                if request.headers.get("authorization"):
                    raise OAuthError("invalid_client", "private_key_jwt only — no Authorization header", 401)
                out = services.rotate_key(await _form(request), ip)
            except OAuthError as e:
                security.seclog.info("oauth service key refused ip=%s error=%s", security.for_log(ip), e.error)
                return error_json(e)
            return JSONResponse(out, headers={"Pragma": "no-cache", "Cache-Control": "no-store"})


        # Self-service: the services that act as the signed-in person. Managed from an interactive session only —
        # never with an API key, an access token or an app password (`session_user`).
        @r.get("/auth/oauth/services")
        def own_services(request: Request):
            user = auth.session_user(request)
            if user is None:
                raise HTTPException(401)
            return auth.list_service_clients(int(user["id"]))


        @r.post("/auth/oauth/services/pairing")
        async def own_service_pairing(request: Request):
            # B-12: a service is a new, lasting way in — only from a fresh confirmation, like an API key.
            user = auth._require_fresh(request)
            b = await auth.json_body(request)
            try:
                return auth.create_service_pairing(int(user["id"]), name=b.get("name"),
                                                   resources=b.get("resources"), roles=b.get("roles"))
            except ConfigError as e:
                raise HTTPException(400, auth.t("api.invalid", reason=str(e)))


        @r.post("/auth/oauth/services/{client_id}/revoke")
        async def own_service_revoke(request: Request, client_id: str):
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
            user = auth.session_user(request)
            if user is None:
                raise HTTPException(401)
            if not auth.revoke_service_client(client_id, user_id=int(user["id"])):
                raise HTTPException(404, auth.t("api.not_found"))
            return {"ok": True}


    # --- own devices (account page) ---
    @r.post("/auth/oauth/devices/{grant_id}/revoke")
    async def device_revoke(request: Request, grant_id: int):
        form = await request.form()
        auth.require_csrf(request, form.get("_csrf"))
        user = auth.session_user(request)
        if user is None:
            return page_error(request, 401, auth.t("oauth.expired"))
        g = auth.store.oauth_grant(grant_id)
        if g is not None and int(g["user_id"]) == int(user["id"]):
            srv.revoke_grant(int(grant_id), "user", auth.client_ip(request))
        return RedirectResponse(auth.browser_path(request, "/auth/account"), 303)

