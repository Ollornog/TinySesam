"""Gate client for Python applications behind TinySesam's gate — Flask, Django, Starlette or any WSGI/ASGI app.

It answers one question per request: *who is this, and may they do this?* It never signs anyone in, holds no session
and issues no token; that stays in TinySesam. The contract is `spec/gate-client.md` in the repository; the test suite
passes every vector of `spec/vectors/`.

Spec version 2: every identity carries `account_kind` (`user` or `service`, from `Remote-Kind` or the claim
`ts_kind`); a request without it is refused. It needs TinySesam and the proxy templates of the same release.

Two modes, chosen explicitly:

- **header mode** (`GateClient(mode="header")`): the proxy asks TinySesam and passes the identity as `Remote-*`
  headers. Safe only when the proxy removes those headers from every client request and is the only way to the
  application (spec §2.1).
- **token mode** (`GateClient(mode="token", issuer=…, audience=…, gate_keys=[…] or jwks_url=…)`): the client verifies
  the Ed25519-signed gate token itself and ignores every `Remote-*` header.

`WSGIMiddleware` and `ASGIMiddleware` identify every request and store the `Identity` (or `None`); the guards
`require_auth`, `require_role`, `require_session` and `require_account_kind` answer 401/403 without a reason.

Only the standard library and `cryptography` (which TinySesam requires anyway); importing this module never imports
FastAPI. Every check of the specification is a small function of its own, so the test suite can switch off exactly one
of them and show that a vector catches it.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import contextvars
import dataclasses
import functools
import hashlib
import inspect
import ipaddress
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from typing import Any, ClassVar, Optional

from .errors import ConfigError

__all__ = [
    "DEFAULT_GATE_COOKIE", "GateClient", "Identity",
    "GateError", "Unauthenticated", "UntrustedPeer", "HeaderError", "InternalError", "TokenError", "MalformedToken",
    "KidError", "SignatureError", "KeyUnavailable", "ClaimsError", "IssuerError", "AudienceError", "LifetimeError",
    "NotYetValid", "Expired",
    "WSGIMiddleware", "ASGIMiddleware", "require_auth", "require_role", "require_session", "require_account_kind",
    "guard_status",
    "current_identity", "Topbar", "TopbarLink", "TopbarApprovals", "parse_topbar", "fetch_topbar",
    "SIGNED_OUT_ACCOUNT", "parse_account", "fetch_account",
]

#: The gate cookie TinySesam sets (`gate_cookie_name`).
DEFAULT_GATE_COOKIE = "__Host-tinysesam_gate"

_ALGORITHM = "EdDSA"
_TOKEN_TYPE = "tinysesam-gate+jwt"
_HEADER_MEMBERS = frozenset({"alg", "typ", "kid"})
_IDENTITY_CLAIMS = ("ts_user", "ts_name", "ts_email", "ts_groups", "ts_id", "ts_auth", "ts_kind")
_AUTH_KINDS = ("session", "oauth", "apikey", "app-password")
_ACCOUNT_KINDS = ("user", "service")
_MAX_TOKEN_BYTES = 4096
_MAX_LEEWAY = 60
_MAX_LIFETIME = 3600
_MAX_SAFE_INTEGER = 2 ** 53 - 1
_SLOTS = ("user", "name", "email", "groups", "id", "auth", "kind")
_DEFAULT_HEADER_NAMES = {"user": "Remote-User", "name": "Remote-Name", "email": "Remote-Email",
                         "groups": "Remote-Groups", "id": "Remote-Id", "auth": "Remote-Auth", "kind": "Remote-Kind"}

# Fetching the key set (spec §5).
_FETCH_TIMEOUT = 5.0           # seconds for one fetch in total: connect, TLS, headers, body
_MAX_JWKS_BYTES = 64 * 1024
_JWKS_DEFAULT_FRESH = 300
_JWKS_MIN_FRESH = 60
_JWKS_MAX_FRESH = 3600
_JWKS_STALE_MAX = 3600         # a set more than this past its freshness is no longer used
_JWKS_MIN_INTERVAL = 10        # at most one fetch attempt per this many seconds
_JWKS_MAX_KEYS = 32
_MAX_REDIRECTS = 3

_KID = re.compile(r"[0-9a-f]{16}")
_SEGMENT = re.compile(r"[A-Za-z0-9_-]*")
_DIGITS = re.compile(r"[0-9]+")
_TCHAR = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*([0-9]+)\s*(?:,|$)", re.IGNORECASE)

_log = logging.getLogger("tinysesam.gate_client")
_ENVIRON_KEY = "tinysesam.identity"
_current: contextvars.ContextVar[Optional["Identity"]] = contextvars.ContextVar("tinysesam_identity", default=None)


# ---------- errors ----------

class GateError(Exception):
    """A refused request. `kind` is the error class of the specification; every class means *not authenticated*.

    `kid` is set when the token named a well-formed key id (safe to log). The message never holds the token, a claim
    or a header value."""

    kind: ClassVar[str] = "internal"

    def __init__(self, detail: str = "", *, kid: str = ""):
        super().__init__(f"{self.kind}: {detail}" if detail else self.kind)
        self.detail = detail
        self.kid = kid


class Unauthenticated(GateError):
    """No or an empty `Remote-User` (header mode), no token (token mode)."""
    kind = "unauthenticated"


class UntrustedPeer(GateError):
    """Header mode with `trusted_proxies`: the request did not come from one of them."""
    kind = "untrusted_peer"


class HeaderError(GateError):
    """A malformed `Remote-*` header (a missing or malformed `Remote-Kind` included), or a forbidden member, `alg` or
    `typ` in the token's header."""
    kind = "header"


class InternalError(GateError):
    """An unexpected failure inside the client — refused like every other error (fail closed)."""
    kind = "internal"


class TokenError(GateError):
    """Base of the token-mode classes below."""


class MalformedToken(TokenError):
    """Size, structure, base64url, JSON, repeated members, more than one gate cookie."""
    kind = "malformed"


class KidError(TokenError):
    """`kid` missing, malformed, or not in the key set."""
    kind = "kid"


class SignatureError(TokenError):
    """The signature has the wrong length or does not verify."""
    kind = "signature"


class KeyUnavailable(TokenError):
    """No key set could be obtained (JWKS)."""
    kind = "key_unavailable"


class ClaimsError(TokenError):
    """A claim of the wrong type, a control character, an inconsistency, a missing or malformed `ts_kind`."""
    kind = "claims"


class IssuerError(TokenError):
    """`iss` is not the configured issuer."""
    kind = "issuer"


class AudienceError(TokenError):
    """`aud` does not name the configured audience."""
    kind = "audience"


class LifetimeError(TokenError):
    """`exp - nbf` is not in (0, 3600]."""
    kind = "lifetime"


class NotYetValid(TokenError):
    """Before `nbf - leeway`."""
    kind = "not_yet_valid"


class Expired(TokenError):
    """At or after `exp + leeway`."""
    kind = "expired"


class _JWKSInvalid(GateError):
    """A key set document of the wrong shape (only ever a failed fetch for the application)."""
    kind = "jwks_invalid"


# ---------- the identity ----------

@dataclasses.dataclass(frozen=True, slots=True)
class Identity:
    """Who the request is. Key your own records by `id`, the only value that survives a rename.

    `kind` says how the request signed in (`session` or `token`), `account_kind` what the account is (`user` or
    `service`): a paired service acting as a person is `token` and `user`."""

    user: str
    name: str
    email: str
    groups: tuple[str, ...]
    id: str
    auth: str
    kind: str
    account_kind: str

    def has_role(self, role: str) -> bool:
        """Exactly `role in groups`: no case folding, no normalization, `admin` implies nothing else."""
        return role in self.groups

    def is_session(self) -> bool:
        """True only when the request signed in with a browser session (`Remote-Auth`/`ts_auth` exactly `session`).
        A token request's groups are incomplete on purpose: never revoke a role because one lacks it."""
        return self.kind == "session"

    def is_service(self) -> bool:
        """True only for a service account (`Remote-Kind`/`ts_kind` exactly `service`)."""
        return self.account_kind == "service"


def _has_control(text: str) -> bool:
    """C0 control characters and DEL — exactly what TinySesam removes before sending."""
    return any(c < " " or c == "\x7f" for c in text)


def _trim_group(part: str) -> str:
    return part.strip(" ")


def _parse_groups(text: str) -> tuple[str, ...]:
    """Split at every comma, trim spaces, drop empty entries and repeats (spec §3.3). No escapes."""
    out: list[str] = []
    for part in text.split(","):
        group = _trim_group(part)
        if group and group not in out:
            out.append(group)
    return tuple(out)


def _kind_of(auth: str) -> str:
    return "session" if auth == "session" else "token"


def _identity(user: str, name: str, email: str, groups: str, uid: str, auth: str, account_kind: str) -> Identity:
    return Identity(user=user, name=name, email=email, groups=_parse_groups(groups), id=uid,
                    auth=auth if auth in _AUTH_KINDS else "", kind=_kind_of(auth), account_kind=account_kind)


# ---------- the account kind (spec v2), one set of rules for both modes ----------
# Each check takes the error class of its mode (HeaderError or ClaimsError) and returns the value it passed, so that
# the test suite can relax exactly one rule.

def _check_kind_present(kind: Any, error: type[GateError]) -> Any:
    if kind is None or kind == "":
        raise error("Remote-Kind/ts_kind missing (TinySesam or proxy older than spec v2?)")
    return kind


def _check_kind_value(kind: Any, error: type[GateError]) -> str:
    if not isinstance(kind, str) or kind not in _ACCOUNT_KINDS:
        raise error("Remote-Kind/ts_kind is not exactly user or service")
    return kind


def _check_kind_consistent(kind: str, auth: Any, error: type[GateError]) -> None:
    if kind == "service" and auth == "session":
        raise error("a service account has no session")


def _account_kind(kind: Any, auth: Any, error: type[GateError]) -> str:
    value = _check_kind_value(_check_kind_present(kind, error), error)
    _check_kind_consistent(value, auth, error)
    return value


# ---------- strict decoding ----------

def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(segment: str) -> bytes:
    """Strict base64url: URL-safe alphabet, no padding, no whitespace, canonical (unused bits zero)."""
    if not _SEGMENT.fullmatch(segment) or len(segment) % 4 == 1:
        raise MalformedToken("base64url alphabet or length")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as e:
        raise MalformedToken("base64url") from e
    if _b64u_encode(raw) != segment:
        raise MalformedToken("base64url not canonical")
    return raw


def _decode_utf8(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedToken("not UTF-8") from e


def _check_bom(text: str) -> str:
    if text.startswith("\ufeff"):
        raise MalformedToken("byte order mark")
    return text


def _unique_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in items:
        if key in out:
            raise MalformedToken("repeated member")
        out[key] = value
    return out


def _json_constant(name: str) -> Any:
    raise MalformedToken(f"JSON constant {name}")


def _strict_json(raw: bytes) -> Any:
    """Strict JSON from UTF-8 bytes: no BOM, no repeated member names, no NaN/Infinity."""
    text = _check_bom(_decode_utf8(raw))
    try:
        return json.loads(text, object_pairs_hook=_unique_pairs, parse_constant=_json_constant)
    except MalformedToken:
        raise
    except (ValueError, RecursionError) as e:
        raise MalformedToken("not JSON") from e


def _json_object(raw: bytes) -> dict[str, Any]:
    value = _strict_json(raw)
    if not isinstance(value, dict):
        raise MalformedToken("not a JSON object")
    return value


# ---------- keys ----------

def _key_id(public: bytes) -> str:
    """The first 16 hex digits of SHA-256 over the 32 raw public key bytes."""
    return hashlib.sha256(public).hexdigest()[:16]


def _parse_gate_key(text: str) -> bytes:
    """The output of `tinysesam gate-key`: 32 raw bytes in standard Base64."""
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError, AttributeError) as e:
        raise ConfigError("gate_keys: not standard Base64") from e
    if len(raw) != 32:
        raise ConfigError("gate_keys: a gate key is 32 bytes")
    return raw


def _jwk_entry(entry: Any) -> Optional[tuple[str, bytes]]:
    """(kid, public key) of a usable JWKS entry, None for one that must be skipped (spec §4.3)."""
    if not isinstance(entry, dict):
        return None
    if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
        return None
    if any(m in entry for m in ("d", "x5u", "x5c", "x5t", "x5t#S256", "jku")):
        return None
    if "alg" in entry and entry["alg"] != _ALGORITHM:
        return None
    if "use" in entry and entry["use"] != "sig":
        return None
    if "key_ops" in entry and not (isinstance(entry["key_ops"], list) and "verify" in entry["key_ops"]):
        return None
    x, kid = entry.get("x"), entry.get("kid")
    if not isinstance(x, str) or not isinstance(kid, str):
        return None
    try:
        public = _b64u_decode(x)
    except MalformedToken:
        return None
    if len(public) != 32 or kid != _key_id(public):
        return None
    return kid, public


def _parse_jwks(doc: Any) -> dict[str, bytes]:
    """kid → public key of every usable entry, in order; a document of the wrong shape is `jwks_invalid`."""
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list) or len(doc["keys"]) > _JWKS_MAX_KEYS:
        raise _JWKSInvalid("shape")
    found = [f for f in (_jwk_entry(e) for e in doc["keys"]) if f]
    kids = [kid for kid, _ in found]
    return {kid: public for kid, public in found if kids.count(kid) == 1}


# ---------- the token, checking order of spec §4.4 ----------

@dataclasses.dataclass(frozen=True, slots=True)
class _Parsed:
    head: dict[str, Any]
    kid: str
    signing_input: bytes
    payload: bytes
    signature: bytes


def _check_size(jws: str) -> None:
    if len(jws.encode("utf-8", "surrogatepass")) > _MAX_TOKEN_BYTES:
        raise MalformedToken("larger than 4096 bytes")


def _split(jws: str) -> tuple[str, str, str]:
    parts = jws.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise MalformedToken("not three segments")
    return parts[0], parts[1], parts[2]


def _check_header_members(head: dict[str, Any]) -> None:
    if set(head) - _HEADER_MEMBERS:
        raise HeaderError("a header member besides alg, typ and kid")


def _check_alg(head: dict[str, Any]) -> None:
    alg = head.get("alg")
    if not (isinstance(alg, str) and alg == _ALGORITHM):
        raise HeaderError("alg is not EdDSA")


def _check_typ(head: dict[str, Any]) -> None:
    typ = head.get("typ")
    if not (isinstance(typ, str) and typ.isascii() and typ.lower() == _TOKEN_TYPE):
        raise HeaderError("typ")


def _check_kid(head: dict[str, Any]) -> str:
    kid = head.get("kid")
    if not isinstance(kid, str) or not _KID.fullmatch(kid):
        raise KidError("kid missing or not 16 lowercase hex digits")
    return kid


def _check_signature_length(head: dict[str, Any], signature: bytes, kid: str) -> None:
    if len(signature) != 64:
        raise SignatureError("not 64 bytes", kid=kid)


def _parse(jws: Any) -> _Parsed:
    """Steps 1–5: everything decided before a key is chosen."""
    if not isinstance(jws, str):
        raise MalformedToken("not a string")
    _check_size(jws)
    h_seg, p_seg, s_seg = _split(jws)
    head_raw, payload, signature = _b64u_decode(h_seg), _b64u_decode(p_seg), _b64u_decode(s_seg)
    head = _json_object(head_raw)
    _check_header_members(head)
    _check_alg(head)
    _check_typ(head)
    kid = _check_kid(head)
    _check_signature_length(head, signature, kid)
    return _Parsed(head=head, kid=kid, signing_input=f"{h_seg}.{p_seg}".encode("ascii"), payload=payload,
                   signature=signature)


def _select_key(parsed: _Parsed, lookup: Callable[[str], bytes]) -> bytes:
    """Step 6: the key comes from the configuration, never from the token."""
    return lookup(parsed.kid)


def _verify_signature(parsed: _Parsed, public: bytes) -> None:
    """Step 7: Ed25519 — the client's constant, never the header's `alg`."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(parsed.signature, parsed.signing_input)
    except (InvalidSignature, ValueError) as e:
        raise SignatureError("Ed25519 verification failed", kid=parsed.kid) from e


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_SAFE_INTEGER


def _check_claim_types(claims: dict[str, Any]) -> None:
    for name in ("iss", "sub"):
        if not isinstance(claims.get(name), str):
            raise ClaimsError(name)
    aud = claims.get("aud")
    if not (isinstance(aud, str) or (isinstance(aud, list) and aud and all(isinstance(a, str) for a in aud))):
        raise ClaimsError("aud")
    for name in ("iat", "nbf", "exp"):
        if not _is_int(claims.get(name)):
            raise ClaimsError(name)
    if "jti" in claims and not isinstance(claims["jti"], str):
        raise ClaimsError("jti")
    for name in _IDENTITY_CLAIMS:
        if name in claims and not isinstance(claims[name], str):
            raise ClaimsError(name)


def _check_sub(claims: dict[str, Any]) -> None:
    if not claims["sub"]:
        raise ClaimsError("sub is empty")


def _check_claim_controls(claims: dict[str, Any]) -> None:
    for name in ("sub", *_IDENTITY_CLAIMS):
        if name in claims and _has_control(str(claims[name])):
            raise ClaimsError(f"control character in {name}")


def _check_ts_id(claims: dict[str, Any]) -> None:
    if "ts_id" in claims and claims["ts_id"] != claims["sub"]:
        raise ClaimsError("ts_id differs from sub")


def _check_iat(claims: dict[str, Any]) -> None:
    if claims["iat"] > claims["nbf"]:
        raise ClaimsError("iat later than nbf")


def _check_issuer(iss: Any, issuer: str) -> None:
    if iss != issuer:
        raise IssuerError()


def _check_audience(aud: Any, audience: str) -> None:
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise AudienceError()


def _check_lifetime(nbf: int, exp: int) -> None:
    if exp <= nbf or exp - nbf > _MAX_LIFETIME:
        raise LifetimeError()


def _check_not_before(nbf: int, now: int, leeway: int) -> None:
    if nbf > now + leeway:
        raise NotYetValid()


def _check_expiry(exp: int, now: int, leeway: int) -> None:
    if exp + leeway <= now:
        raise Expired()


def _check_claims(claims: dict[str, Any], *, issuer: str, audience: str, now: int, leeway: int) -> None:
    """Steps 9–10: types and consistency (`ts_kind` included), then issuer, audience, lifetime, nbf, exp."""
    _check_claim_types(claims)
    _check_sub(claims)
    _check_claim_controls(claims)
    _check_ts_id(claims)
    _check_iat(claims)
    _account_kind(claims.get("ts_kind"), claims.get("ts_auth"), ClaimsError)
    _check_issuer(claims["iss"], issuer)
    _check_audience(claims["aud"], audience)
    _check_lifetime(claims["nbf"], claims["exp"])
    _check_not_before(claims["nbf"], now, leeway)
    _check_expiry(claims["exp"], now, leeway)


def _verify(jws: Any, lookup: Callable[[str], bytes], *, issuer: str, audience: str, now: int,
            leeway: int) -> dict[str, Any]:
    parsed = _parse(jws)
    public = _select_key(parsed, lookup)
    _verify_signature(parsed, public)
    try:
        claims = _json_object(parsed.payload)        # step 8 — only after the signature
        _check_claims(claims, issuer=issuer, audience=audience, now=now, leeway=leeway)
    except GateError as e:
        e.kid = parsed.kid
        raise
    return claims


def _identity_from_claims(claims: dict[str, Any]) -> Identity:
    return _identity(claims.get("ts_user", ""), claims.get("ts_name", ""), claims.get("ts_email", ""),
                     str(claims.get("ts_groups", "")), claims["sub"], claims.get("ts_auth", ""),
                     _account_kind(claims.get("ts_kind"), claims.get("ts_auth"), ClaimsError))


def _check_leeway(leeway: Any) -> int:
    if not isinstance(leeway, int) or isinstance(leeway, bool) or not 0 <= leeway <= _MAX_LEEWAY:
        raise ConfigError(f"leeway must be an integer from 0 to {_MAX_LEEWAY} seconds")
    return leeway


# ---------- header mode ----------

def _decode_header(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise HeaderError("not UTF-8") from e


def _check_header_controls(text: str) -> str:
    if _has_control(text):
        raise HeaderError("control character")
    return text


def _check_remote_id(rid: str) -> None:
    if rid and not _DIGITS.fullmatch(rid):
        raise HeaderError("Remote-Id is not ASCII digits")


def _octets(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return value.encode("latin-1")       # PEP 3333 and most frameworks: one code point per octet
        except UnicodeEncodeError as e:
            raise HeaderError("a header value that is not octets") from e
    raise HeaderError("a header value of the wrong type")


def _field_name(name: Any) -> str:
    if isinstance(name, (bytes, bytearray)):
        name = bytes(name).decode("latin-1")
    if not isinstance(name, str):
        raise HeaderError("a header name of the wrong type")
    return name.lower()


def _collect(pairs: Iterable[tuple[Any, Any]], wanted: Iterable[str]) -> dict[str, bytes]:
    """name (lower case) → value of each wanted field; a field that occurs twice (in any spelling) is an error."""
    want = {w.lower() for w in wanted}
    out: dict[str, bytes] = {}
    for name, value in pairs:
        key = _field_name(name)
        if key not in want:
            continue
        if isinstance(value, list):
            if len(value) != 1:
                raise HeaderError("a field more than once")
            value = value[0]
        if key in out:
            raise HeaderError("a field more than once")
        out[key] = _octets(value)
    return out


def _identity_from_headers(pairs: Iterable[tuple[Any, Any]], names: Mapping[str, str]) -> Identity:
    found = _collect(pairs, names.values())
    values: dict[str, str] = {}
    for slot in _SLOTS:
        raw = found.get(names[slot].lower())
        if raw is not None:
            values[slot] = _check_header_controls(_decode_header(raw))
    if not values.get("user"):
        raise Unauthenticated()
    _check_remote_id(values.get("id", ""))
    account_kind = _account_kind(values.get("kind"), values.get("auth"), HeaderError)
    return _identity(values["user"], values.get("name", ""), values.get("email", ""), values.get("groups", ""),
                     values.get("id", ""), values.get("auth", ""), account_kind)


def _pairs(headers: Any) -> list[tuple[Any, Any]]:
    if isinstance(headers, Mapping):
        return list(headers.items())
    return list(headers)


# ---------- the JWKS cache, spec §5 ----------

@dataclasses.dataclass(frozen=True, slots=True)
class _FetchResult:
    status: int = 0
    cache_control: str = ""
    body: Optional[bytes] = None
    error: str = ""


def _freshness(cache_control: str) -> int:
    match = _MAX_AGE.search(cache_control or "")
    fresh = int(match.group(1)) if match else _JWKS_DEFAULT_FRESH
    return min(max(fresh, _JWKS_MIN_FRESH), _JWKS_MAX_FRESH)


def _interpret(result: _FetchResult) -> Optional[tuple[dict[str, bytes], int]]:
    """A key set and its freshness, or None for a failed fetch (which never replaces the cached set)."""
    if result.error or result.status != 200 or result.body is None or len(result.body) > _MAX_JWKS_BYTES:
        return None
    try:
        keys = _parse_jwks(_strict_json(result.body))
    except GateError:
        return None
    if not keys:
        return None
    return keys, _freshness(result.cache_control)


class _JWKSCache:
    """The last good key set and when to fetch. A request waits at most for the deadline of a running fetch; requests
    that need keys while a fetch runs share it."""

    def __init__(self, fetch: Callable[[], _FetchResult], wait: Optional[float] = None):
        self._fetch, self._wait = fetch, wait
        self._lock = threading.Lock()
        self._keys: Optional[dict[str, bytes]] = None
        self._fresh_until = 0
        self._last_attempt: Optional[int] = None
        self._running: Optional[tuple[threading.Event, float]] = None

    def lookup(self, kid: str, now: int) -> bytes:
        fetched = False
        with self._lock:
            stale = self._keys is None or now >= self._fresh_until
        if stale:
            fetched = self._maybe_fetch(now)
        with self._lock:
            keys, fresh_until = self._keys, self._fresh_until
        if keys is None or now >= fresh_until + _JWKS_STALE_MAX:
            raise KeyUnavailable("no usable key set", kid=kid)
        if kid in keys:
            return keys[kid]
        if not fetched and self._maybe_fetch(now):
            with self._lock:
                keys = self._keys or {}
            if kid in keys:
                return keys[kid]
        raise KidError("kid not in the key set", kid=kid)

    def _maybe_fetch(self, now: int) -> bool:
        """Start a fetch if the rate allows, or join the running one; wait at most until its deadline."""
        with self._lock:
            if self._running is not None:
                done, deadline = self._running
            elif self._last_attempt is not None and now - self._last_attempt < _JWKS_MIN_INTERVAL:
                return False
            else:
                self._last_attempt = now
                wait = _FETCH_TIMEOUT if self._wait is None else self._wait
                done, deadline = threading.Event(), time.monotonic() + wait
                self._running = (done, deadline)
                threading.Thread(target=self._run, args=(done, deadline, now), name="tinysesam-jwks",
                                 daemon=True).start()
        done.wait(max(0.0, deadline - time.monotonic()))
        with self._lock:
            if self._running is not None and self._running[0] is done and time.monotonic() >= deadline:
                self._running = None        # past its deadline: a failed fetch, nobody waits for it any longer
        return True

    def _run(self, done: threading.Event, deadline: float, now: int) -> None:
        got = None
        try:
            got = _interpret(self._fetch())
        except Exception:   # noqa: BLE001 — a failing fetcher is a failed fetch, never a crash
            got = None
        finally:
            with self._lock:
                if got is not None and time.monotonic() < deadline:
                    self._keys, self._fresh_until = got[0], now + got[1]
                if self._running is not None and self._running[0] is done:
                    self._running = None
            done.set()


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to the same host and never from https to http."""
    max_redirections = _MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if new.netloc != old.netloc or (old.scheme == "https" and new.scheme != "https"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read_limited(url: str, headers: Mapping[str, str], timeout: float, limit: int) -> _FetchResult:
    """One GET with a total deadline and a body limit; a redirect only to the same host."""
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(_SameHostRedirects)
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as resp:
            status, cache_control = resp.status, resp.headers.get("Cache-Control", "")
            body = bytearray()
            while True:
                if time.monotonic() > deadline:
                    return _FetchResult(error="deadline")
                chunk = resp.read1(16384)
                if not chunk:
                    break
                body += chunk
                if len(body) > limit:
                    return _FetchResult(error="body too large")
    except urllib.error.HTTPError as e:
        e.close()
        return _FetchResult(status=e.code, error="status")
    except (OSError, ValueError, urllib.error.URLError) as e:
        return _FetchResult(error=type(e).__name__)
    if time.monotonic() > deadline:
        return _FetchResult(error="deadline")
    return _FetchResult(status=status, cache_control=cache_control, body=bytes(body))


def _check_fetch_url(url: Any, what: str) -> str:
    if not isinstance(url, str) or not url:
        raise ConfigError(f"{what}: a URL is required")
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        raise ConfigError(f"{what}: no host")
    if parts.scheme == "https":
        return url
    if parts.scheme == "http":
        host = parts.hostname
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if loopback:
            return url
    raise ConfigError(f"{what}: https only (plain http only to a loopback address)")


# ---------- the client ----------

class GateClient:
    """Identifies requests in one explicitly chosen mode. Configuration errors raise `ConfigError` at construction.

    Header mode: `GateClient(mode="header", trusted_proxies=["127.0.0.1"], header_names=None)`.
    Token mode: `GateClient(mode="token", issuer=…, audience=…, gate_keys=[…] or jwks_url=…, leeway=0,
    cookie_name=None or token_header=None)`.
    """

    def __init__(self, *, mode: str, trusted_proxies: Optional[Iterable[str]] = None,
                 header_names: Optional[Mapping[str, str]] = None, issuer: Optional[str] = None,
                 audience: Optional[str] = None, gate_keys: Optional[Iterable[str]] = None,
                 jwks_url: Optional[str] = None, leeway: int = 0, cookie_name: Optional[str] = None,
                 token_header: Optional[str] = None):
        if mode not in ("header", "token"):
            raise ConfigError('mode must be "header" or "token" — the client never guesses')
        self.mode = mode
        self._names: dict[str, str] = dict(_DEFAULT_HEADER_NAMES)
        self._proxies: Optional[list[Any]] = None
        self._cache: Optional[_JWKSCache] = None
        self._keys: dict[str, bytes] = {}
        self._issuer, self._audience, self._leeway = "", "", 0
        self._cookie, self._token_header = DEFAULT_GATE_COOKIE, ""
        token_settings = {"issuer": issuer, "audience": audience, "gate_keys": gate_keys, "jwks_url": jwks_url,
                          "cookie_name": cookie_name, "token_header": token_header}
        if mode == "header":
            given = sorted(k for k, v in token_settings.items() if v is not None) + (["leeway"] if leeway else [])
            if given:
                raise ConfigError(f"header mode takes no token settings: {', '.join(given)}")
            if header_names is not None:
                self._names = self._check_names(header_names)
            if trusted_proxies is not None:
                self._proxies = self._check_proxies(trusted_proxies)
            return
        if header_names is not None or trusted_proxies is not None:
            raise ConfigError("token mode ignores every Remote-* header: no header_names, no trusted_proxies")
        for field, value in (("issuer", issuer), ("audience", audience)):
            if not isinstance(value, str) or not value:
                raise ConfigError(f"token mode needs {field} (from the configuration, never from the request)")
        self._issuer, self._audience = str(issuer), str(audience)
        self._leeway = _check_leeway(leeway)
        if (gate_keys is None) == (jwks_url is None):
            raise ConfigError("token mode needs exactly one key source: gate_keys or jwks_url")
        if gate_keys is not None:
            if isinstance(gate_keys, str):
                gate_keys = [gate_keys]
            for text in gate_keys:
                public = _parse_gate_key(text)
                self._keys[_key_id(public)] = public
            if not self._keys:
                raise ConfigError("gate_keys: no key")
        else:
            url = _check_fetch_url(jwks_url, "jwks_url")
            if urllib.parse.urlsplit(url).path.rstrip("/").endswith("/approvals/jwks.json"):
                raise ConfigError("jwks_url: that is the APPROVAL key set — gate tokens have their own, "
                                  "https://<auth host>/auth/gate/jwks.json")
            self._cache = _JWKSCache(lambda: _read_limited(url, {"Accept": "application/json"}, _FETCH_TIMEOUT,
                                                           _MAX_JWKS_BYTES))
        if cookie_name is not None and token_header is not None:
            raise ConfigError("the token comes from exactly one source: cookie_name or token_header")
        if token_header is not None:
            self._token_header = self._check_field(token_header, "token_header")
        elif cookie_name is not None:
            if not isinstance(cookie_name, str) or not _TCHAR.fullmatch(cookie_name):
                raise ConfigError("cookie_name: not a valid cookie name")
            self._cookie = cookie_name

    @staticmethod
    def _check_field(name: Any, what: str) -> str:
        if not isinstance(name, str) or not _TCHAR.fullmatch(name):
            raise ConfigError(f"{what}: not a valid header name")
        return name

    def _check_names(self, header_names: Mapping[str, str]) -> dict[str, str]:
        unknown = sorted(set(header_names) - set(_SLOTS))
        if unknown:
            raise ConfigError(f"header_names: unknown slot(s) {unknown}; slots are {', '.join(_SLOTS)}")
        names = dict(_DEFAULT_HEADER_NAMES)
        for slot, name in header_names.items():
            names[slot] = self._check_field(name, f"header_names[{slot!r}]")
        lowered = [n.lower() for n in names.values()]
        if len(set(lowered)) != len(lowered):
            raise ConfigError("header_names: a header name used twice")
        return names

    @staticmethod
    def _check_proxies(proxies: Iterable[str]) -> list[Any]:
        if isinstance(proxies, str):
            proxies = [proxies]
        out = []
        for p in proxies:
            try:
                out.append(ipaddress.ip_network(p, strict=False))
            except (TypeError, ValueError) as e:
                raise ConfigError(f"trusted_proxies: {p!r} is no address or network") from e
        if not out:
            raise ConfigError("trusted_proxies: empty — leave it out instead (None)")
        return out

    def _trusted(self, peer: Optional[str]) -> bool:
        if self._proxies is None:
            return True
        if not peer:
            return False
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return any(address in net for net in self._proxies)

    def identify(self, headers: Any, *, peer: Optional[str] = None, now: Optional[int] = None) -> Identity:
        """The identity of one request, or a `GateError`.

        `headers` is a mapping or a list of `(name, value)` pairs — keep repeated fields as separate pairs, the
        client refuses them. A value is bytes or a str of octets (one code point per byte, as WSGI delivers it).
        `peer` is the address the connection came from (checked against `trusted_proxies` in header mode)."""
        pairs = _pairs(headers)
        if self.mode == "header":
            if not self._trusted(peer):
                raise UntrustedPeer()
            return _identity_from_headers(pairs, self._names)
        return self.verify(self._token(pairs), now=now)[0]

    def _token(self, pairs: list[tuple[Any, Any]]) -> str:
        if self._token_header:
            try:
                found = _collect(pairs, [self._token_header])
            except HeaderError as e:
                raise MalformedToken("more than one token header") from e
            raw = found.get(self._token_header.lower())
            if not raw:
                raise Unauthenticated()
            return raw.decode("latin-1")
        values = []
        for name, value in pairs:
            if _field_name(name) != "cookie":
                continue
            for item in (value if isinstance(value, list) else [value]):
                for part in _octets(item).decode("latin-1").split(";"):
                    key, sep, val = part.strip().partition("=")
                    if sep and key.strip() == self._cookie:
                        values.append(val.strip())
        if len(values) > 1:
            raise MalformedToken("more than one gate cookie")
        if not values or not values[0]:
            raise Unauthenticated()
        return values[0]

    def verify(self, jws: str, *, now: Optional[int] = None) -> tuple[Identity, dict[str, Any]]:
        """Token mode: check one gate token without a request; the identity and the claims, or a `GateError`."""
        if self.mode != "token":
            raise ConfigError("verify() needs token mode")
        at = int(time.time()) if now is None else now
        lookup: Callable[[str], bytes]
        if self._cache is not None:
            cache = self._cache
            lookup = functools.partial(lambda kid, t: cache.lookup(kid, t), t=at)
        else:
            lookup = self._static_lookup
        claims = _verify(jws, lookup, issuer=self._issuer, audience=self._audience, now=at, leeway=self._leeway)
        return _identity_from_claims(claims), claims

    def _static_lookup(self, kid: str) -> bytes:
        public = self._keys.get(kid)
        if public is None:
            raise KidError("kid not in the key set", kid=kid)
        return public

    @property
    def _may_block(self) -> bool:
        """True when identifying may wait for a key set fetch (token mode with `jwks_url`)."""
        return self._cache is not None

    def _wanted(self) -> list[str]:
        if self.mode == "header":
            return list(self._names.values())
        return [self._token_header] if self._token_header else ["Cookie"]


def _identify_or_none(gate: GateClient, pairs: list[tuple[Any, Any]], peer: Optional[str]) -> Optional[Identity]:
    """Fail closed: every error, an unexpected one included, means no identity. Logs the class and the kid only."""
    try:
        return gate.identify(pairs, peer=peer)
    except Unauthenticated:
        return None
    except GateError as e:
        _log.info("gate refused a request: class=%s kid=%s", e.kind, e.kid or "-")
    except Exception as e:  # noqa: BLE001 — fail closed (spec §6)
        _log.warning("gate refused a request: class=internal error=%s", type(e).__name__)
    return None


# ---------- WSGI and ASGI ----------

class WSGIMiddleware:
    """Identifies every request and stores the `Identity` (or `None`) in `environ["tinysesam.identity"]` and for
    `current_identity()`. Lets every request through; guard routes with `require_*` or `guard_status`.

    WSGI servers join or drop repeated header fields before the application sees them, so in header mode only the
    proxy's duty to remove client `Remote-*` headers (spec §2.1) protects against repeats here; the ASGI middleware
    sees and refuses them."""

    def __init__(self, app: Callable[..., Any], gate: GateClient):
        if not isinstance(gate, GateClient):
            raise ConfigError("WSGIMiddleware needs a GateClient")
        self.app, self.gate = app, gate

    def __call__(self, environ: dict[str, Any], start_response: Callable[..., Any]) -> Any:
        pairs = []
        for name in self.gate._wanted():
            key = "HTTP_" + name.upper().replace("-", "_")
            if key in environ:
                pairs.append((name, environ[key]))
        identity = _identify_or_none(self.gate, pairs, environ.get("REMOTE_ADDR"))
        environ[_ENVIRON_KEY] = identity
        token = _current.set(identity)
        try:
            return self.app(environ, start_response)
        finally:
            _current.reset(token)


class ASGIMiddleware:
    """Identifies every HTTP and WebSocket request and stores the `Identity` (or `None`) in
    `scope["tinysesam.identity"]` and for `current_identity()`. Starlette: `app.add_middleware(ASGIMiddleware,
    gate=gate)`. With `jwks_url` the check runs in a worker thread, so a key fetch never blocks the event loop."""

    def __init__(self, app: Callable[..., Any], gate: GateClient):
        if not isinstance(gate, GateClient):
            raise ConfigError("ASGIMiddleware needs a GateClient")
        self.app, self.gate = app, gate

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope.get("type") not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        pairs = list(scope.get("headers") or [])
        client = scope.get("client")
        peer = client[0] if client else None
        if self.gate._may_block:
            identity = await asyncio.to_thread(_identify_or_none, self.gate, pairs, peer)
        else:
            identity = _identify_or_none(self.gate, pairs, peer)
        scope[_ENVIRON_KEY] = identity
        token = _current.set(identity)
        try:
            await self.app(scope, receive, send)
        finally:
            _current.reset(token)


def current_identity(source: Any = None) -> Optional[Identity]:
    """The identity the middleware stored: from a WSGI environ or ASGI scope, from a request object that carries one
    (`.environ` in Flask, `.META` in Django, `.scope` in Starlette), or — without an argument — from the
    request being handled. `None` when nobody is signed in or no middleware ran."""
    if source is None:
        return _current.get()
    for attribute in ("environ", "META", "scope"):
        inner = getattr(source, attribute, None)
        if isinstance(inner, Mapping):
            source = inner
            break
    if isinstance(source, Mapping):
        value = source.get(_ENVIRON_KEY)
        return value if isinstance(value, Identity) else None
    return None


def guard_status(identity: Optional[Identity], *, role: Optional[str] = None, session: bool = False,
                 account_kind: Optional[str] = None) -> Optional[int]:
    """None when the request may pass, else the status to answer: 401 without an identity, 403 when the role, the
    session or the account kind (`user`/`service`) is missing. For view decorators in any framework."""
    if not isinstance(identity, Identity):
        return 401
    if session and not identity.is_session():
        return 403
    if account_kind is not None and identity.account_kind != account_kind:
        return 403
    if role is not None and not identity.has_role(role):
        return 403
    return None


_REASONS = {401: "401 Unauthorized", 403: "403 Forbidden"}


def _deny_headers(body: bytes) -> list[tuple[str, str]]:
    return [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store"),
            ("Content-Length", str(len(body)))]


def _is_asgi(app: Any) -> bool:
    return inspect.iscoroutinefunction(app) or inspect.iscoroutinefunction(getattr(app, "__call__", None))


def _guard(app: Callable[..., Any], role: Optional[str], session: bool,
           account_kind: Optional[str] = None) -> Callable[..., Any]:
    if not callable(app):
        raise ConfigError("a guard wraps a WSGI or ASGI application")
    if _is_asgi(app):
        async def asgi_guard(scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
            if scope.get("type") not in ("http", "websocket"):
                await app(scope, receive, send)
                return
            status = guard_status(current_identity(scope), role=role, session=session, account_kind=account_kind)
            if status is None:
                await app(scope, receive, send)
            elif scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                body = _REASONS[status][4:].encode("ascii")
                await send({"type": "http.response.start", "status": status,
                            "headers": [(k.lower().encode("latin-1"), v.encode("latin-1"))
                                        for k, v in _deny_headers(body)]})
                await send({"type": "http.response.body", "body": body})
        return functools.update_wrapper(asgi_guard, app)

    def wsgi_guard(environ: dict[str, Any], start_response: Callable[..., Any]) -> Any:
        status = guard_status(current_identity(environ), role=role, session=session, account_kind=account_kind)
        if status is None:
            return app(environ, start_response)
        body = _REASONS[status][4:].encode("ascii")
        start_response(_REASONS[status], _deny_headers(body))
        return [body]
    try:
        return functools.update_wrapper(wsgi_guard, app)
    except (AttributeError, TypeError):
        return wsgi_guard


def require_auth(app: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a WSGI or ASGI application: 401 without an identity. Needs the middleware in front (else always 401)."""
    return _guard(app, None, False)


def require_role(role: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """`require_role("editors")(app)`: 401 without an identity, 403 without the role (compared exactly)."""
    if not isinstance(role, str) or not role:
        raise ConfigError("require_role needs a role name")
    return lambda app: _guard(app, role, False)


def require_session(app: Callable[..., Any]) -> Callable[..., Any]:
    """401 without an identity, 403 for a token request (API key, OAuth, app password): for actions a token must
    never perform."""
    return _guard(app, None, True)


def require_account_kind(kind: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """`require_account_kind("user")(app)`: 401 without an identity, 403 for another account kind — e.g. a route that
    only people may use, or (`"service"`) an endpoint only for service accounts."""
    if kind not in _ACCOUNT_KINDS:
        raise ConfigError('require_account_kind takes "user" or "service"')
    return lambda app: _guard(app, None, False, kind)


# ---------- top bar data, spec §8 ----------

@dataclasses.dataclass(frozen=True, slots=True)
class TopbarLink:
    """One link of the top bar; render `title` as text, never as markup."""
    title: str
    href: str


@dataclasses.dataclass(frozen=True, slots=True)
class TopbarApprovals:
    """How many approvals wait for this account and where to decide them (spec §8, with approvals switched on). Show
    the number with a word ("Approvals (2)"), never as a coloured dot alone."""
    pending: int
    href: str


@dataclasses.dataclass(frozen=True, slots=True)
class Topbar:
    """TinySesam's top bar data reduced to what an application may render. Do not cache it across sessions."""
    brand: str = ""
    signed_in: bool = False
    name: Optional[str] = None
    links: tuple[TopbarLink, ...] = ()
    menu_links: tuple[TopbarLink, ...] = ()
    account: Optional[str] = None
    admin_panel: Optional[str] = None
    logout: Optional[str] = None
    approvals: Optional[TopbarApprovals] = None

    def to_dict(self) -> dict[str, Any]:
        """The normalized form of spec §8 (`links` and `menu_links` as lists of `{title, href}`, `approvals` as
        `{pending, href}` or None)."""
        approvals = None if self.approvals is None else {"pending": self.approvals.pending,
                                                         "href": self.approvals.href}
        return {"brand": self.brand, "signed_in": self.signed_in, "name": self.name,
                "links": [{"title": link.title, "href": link.href} for link in self.links],
                "menu_links": [{"title": link.title, "href": link.href} for link in self.menu_links],
                "account": self.account, "admin_panel": self.admin_panel, "logout": self.logout,
                "approvals": approvals}


def _safe_href(href: Any) -> bool:
    if not isinstance(href, str) or _has_control(href) or any(c.isspace() for c in href):
        return False
    if href.lower().startswith(("https://", "http://")):
        return True
    return href.startswith("/") and not href.startswith(("//", "/\\"))


def _topbar_links(raw: Any) -> tuple[TopbarLink, ...]:
    """The safe `{title, href}` entries of a link list; anything that is no list counts as none."""
    return tuple(TopbarLink(link["title"], link["href"]) for link in (raw if isinstance(raw, list) else [])
                 if isinstance(link, dict) and isinstance(link.get("title"), str) and _safe_href(link.get("href")))


def parse_topbar(data: Any) -> Topbar:
    """Normalize the answer of `/.tinysesam/topbar.json` (or `/auth/topbar.json`): signed out on any doubt, unsafe
    links (`javascript:`, `data:`, `//host`) dropped."""
    if not isinstance(data, dict):
        return Topbar()
    brand = data["brand"] if isinstance(data.get("brand"), str) else ""
    if data.get("signed_in") is not True or not isinstance(data.get("name"), str):
        return Topbar(brand=brand)
    links, menu_links = _topbar_links(data.get("links")), _topbar_links(data.get("menu_links"))
    slots: dict[str, Optional[str]] = {}
    for slot in ("account", "admin_panel"):
        entry = data.get(slot)
        ok = isinstance(entry, dict) and entry.get("shown") is True and _safe_href(entry.get("href"))
        slots[slot] = entry["href"] if ok and isinstance(entry, dict) else None
    logout = data.get("logout")
    slots["logout"] = logout["href"] if isinstance(logout, dict) and _safe_href(logout.get("href")) else None
    return Topbar(brand=brand, signed_in=True, name=data["name"], links=links, menu_links=menu_links,
                  approvals=_topbar_approvals(data.get("approvals")), **slots)


def _count(value: Any) -> Optional[int]:
    """A count or a time of the top bar and the account overview: a JSON integer from 0 to 2^53 − 1, else None."""
    return value if _is_int(value) else None


def _topbar_approvals(raw: Any) -> Optional[TopbarApprovals]:
    """`approvals` of spec §8: a count of at least 0 and a safe `href`, or nothing at all."""
    if not isinstance(raw, dict):
        return None
    pending, href = _count(raw.get("pending")), raw.get("href")
    if pending is None or not isinstance(href, str) or not _safe_href(href):
        return None
    return TopbarApprovals(pending, href)


def _tinysesam_cookies(cookie_header: str) -> str:
    keep = []
    for part in cookie_header.split(";"):
        name = part.strip().partition("=")[0].strip()
        if name.startswith(("tinysesam_", "__Host-tinysesam_")):
            keep.append(part.strip())
    return "; ".join(keep)


def _fetch_json(url: str, what: str, cookie_header: str) -> Any:
    """GET with only TinySesam's cookies of the request, 5-second deadline, 64 KiB; the strict JSON of a 200 answer,
    or None on any failure."""
    target = _check_fetch_url(url, what)
    headers = {"Accept": "application/json"}
    cookies = _tinysesam_cookies(cookie_header or "")
    if cookies:
        headers["Cookie"] = cookies
    result = _read_limited(target, headers, _FETCH_TIMEOUT, _MAX_JWKS_BYTES)
    if result.error or result.status != 200 or result.body is None:
        return None
    try:
        return _strict_json(result.body)
    except GateError:
        return None


def fetch_topbar(url: str, cookie_header: str = "") -> Topbar:
    """Fetch the top bar server-side, forwarding only TinySesam's cookies of the request (`tinysesam_*`,
    `__Host-tinysesam_*`); 5-second deadline, 64 KiB. Signed out on any failure."""
    data = _fetch_json(url, "fetch_topbar", cookie_header)
    return Topbar() if data is None else parse_topbar(data)


# ---------- the own account as data, spec §8a ----------

#: The normalized result for a person who is not signed in (any answer but a 200 with `signed_in: true`).
SIGNED_OUT_ACCOUNT: Mapping[str, Any] = {"signed_in": False, "account": None, "sign_in": None, "sessions": None,
                                         "programs": None, "approvals": None, "links": None}
_ACCOUNT_LINKS = ("account", "sessions", "totp", "passkeys", "devices", "app_passwords", "services", "approvals")


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _flag(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _texts(value: Any) -> Optional[list[str]]:
    """A list of texts: its string entries in order, every other entry dropped; None when it is no list."""
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else None


def _href(value: Any) -> Optional[str]:
    return value if _safe_href(value) else None


def _group(value: Any) -> dict[str, Any]:
    """A member that is always an object in the answer: anything else reads as an empty one (every leaf None)."""
    return value if isinstance(value, dict) else {}


def _items(value: Any, fields: Mapping[str, Callable[[Any], Any]]) -> list[dict[str, Any]]:
    """The object entries of a list, each reduced to `fields`; an entry that is no object is dropped."""
    return [{k: read(e.get(k)) for k, read in fields.items()} for e in value if isinstance(e, dict)]


_USED = {"name": _text, "created_at": _count, "last_used": _count}
_APP_PASSWORD = {**_USED, "expires_at": _count}
_SESSION = {"created_at": _count, "last_seen": _count, "method": _text, "device": _text, "current": _flag}


def _offered_list(value: Any, fields: Mapping[str, Callable[[Any], Any]]) -> Optional[list[dict[str, Any]]]:
    """A list that is None when the installation does not offer it."""
    return _items(value, fields) if isinstance(value, list) else None


def parse_account(data: Any) -> dict[str, Any]:
    """Normalize the answer of `/.tinysesam/account.json` (or `/auth/account.json`), spec §8a: signed out
    (`SIGNED_OUT_ACCOUNT`) unless it is an object with `signed_in` exactly True; otherwise every member of §8a is present,
    a member of the wrong type reads as missing (None), an `href` that is no safe link becomes None, unknown members are
    dropped. Every string is text, never markup. Do not cache it across sessions."""
    if not isinstance(data, dict) or data.get("signed_in") is not True:
        return dict(SIGNED_OUT_ACCOUNT)
    account, sign_in = _group(data.get("account")), _group(data.get("sign_in"))
    sessions, programs, links = _group(data.get("sessions")), _group(data.get("programs")), _group(data.get("links"))
    totp, passkeys = sign_in.get("totp"), sign_in.get("passkeys")
    approvals = data.get("approvals")
    pending = _count(approvals.get("pending")) if isinstance(approvals, dict) else None
    return {
        "signed_in": True,
        "account": {"username": _text(account.get("username")), "display_name": _text(account.get("display_name")),
                    "source": _texts(account.get("source"))},
        "sign_in": {
            "password": _text(sign_in.get("password")),
            "totp": {"enabled": _flag(totp.get("enabled")), "recovery_left": _count(totp.get("recovery_left")),
                     "recovery_low": _flag(totp.get("recovery_low"))} if isinstance(totp, dict) else None,
            "passkeys": {"count": _count(passkeys.get("count")),
                         "items": _items(passkeys.get("items"), _USED) if isinstance(passkeys.get("items"), list)
                         else []} if isinstance(passkeys, dict) else None,
            "pin": _flag(sign_in.get("pin"))},
        "sessions": {"count": _count(sessions.get("count")),
                     "items": _items(sessions["items"], _SESSION) if isinstance(sessions.get("items"), list) else []},
        "programs": {"oauth": _offered_list(programs.get("oauth"), _USED),
                     "services": _offered_list(programs.get("services"), _USED),
                     "app_passwords": _offered_list(programs.get("app_passwords"), _APP_PASSWORD),
                     "api_keys_active": _count(programs.get("api_keys_active"))},
        "approvals": None if pending is None else {"pending": pending},
        "links": {name: _href(links.get(name)) for name in _ACCOUNT_LINKS},
    }


def fetch_account(url: str, cookie_header: str = "") -> dict[str, Any]:
    """Fetch the own account overview server-side (`https://<auth host>/auth/account.json`, or
    `/.tinysesam/account.json` on the application's host), forwarding only TinySesam's cookies of the request;
    5-second deadline, 64 KiB. Signed out on any failure — a 401 (no full browser session), a 404, a 429 included."""
    data = _fetch_json(url, "fetch_account", cookie_header)
    return dict(SIGNED_OUT_ACCOUNT) if data is None else parse_account(data)

