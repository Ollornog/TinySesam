"""The signed one-time confirmation of an application action (approvals, stage B) — issuing and the reference check.

After a person confirmed an action of an application with a step-up, the application picks up exactly one
confirmation (`GET /auth/api/approvals/{id}`) and checks it before it carries the action out:

    from tinysesam.approval_token import verify

    claims = verify(token, keys=jwks_document, issuer="https://auth.example.com", app_id="example",
                    expect_type="example.collection.delete_permanently",
                    expect_fields={"collection": "c_81f2", "name": "Project Alpha"},
                    expect_sub="42", jti_store=remember_once)

The contract for every language is `spec/approval-token.md` with the vectors `spec/vectors/approval.json`; this
module is its Python reference, and the vectors come from `issue` below (`scripts/_approval_vectors.py`).

The confirmation is a JWS (Ed25519) with its own type, `tinysesam-approval+jwt`, signed with its own key (purpose
`approval`, `keys.APPROVAL`) — never the gate key: the proxy checks gate tokens by the key alone, so only a separate
key keeps a confirmation out of a gate cookie and a gate token out of an application's approval check (RFC 8725
§3.11/§3.12). `aud` is ONE string, the application's id; `authorization_details` holds exactly ONE entry, the action
and its fields exactly as stored (RFC 9396); `ts_payload_sha256` is SHA-256 over the RFC 8785 form of that entry; `jti`
is the approval id, handed out once. The application remembers the `jti` until `exp` (step 12 of `verify`), so a copy
taken between pickup and execution is worthless.

Only the standard library, `cryptography` and the strict decoding of `tinysesam.gate_client` (which never imports
FastAPI). Every check is a small module-level function, so `tests/_approval_relax.py` can switch off exactly one of
them and show that a vector catches it.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any, Optional

from . import gate_client as _gc
from .errors import ConfigError

__all__ = [
    "TOKEN_TYPE", "MAX_LIFETIME", "MAX_LEEWAY", "issue", "verify", "key_set", "payload_digest", "canonical",
    "ApprovalTypeError", "ApprovalFieldsError", "SubjectError", "NonceError", "ReplayError",
]

#: The explicit type of a confirmation (RFC 8725 §3.11) — never `tinysesam-gate+jwt`.
TOKEN_TYPE = "tinysesam-approval+jwt"
#: The longest lifetime (`exp - nbf`) a confirmation may have, in seconds; `approval_token_ttl_sec` stays within it.
MAX_LIFETIME = 300
#: The largest clock leeway a checking application may allow, in seconds.
MAX_LEEWAY = 30
#: The longest `jti`, `nonce` and `act.sub` a confirmation may carry.
_MAX_TEXT = 128
_ALGORITHM = "EdDSA"
_HEADER_MEMBERS = frozenset({"alg", "typ", "kid"})
#: The claims every confirmation carries (step 9); `nonce` is optional.
_REQUIRED = ("iss", "aud", "sub", "iat", "nbf", "exp", "jti", "auth_time", "amr", "act", "authorization_details",
             "ts_payload_sha256")


# ---------- errors (beyond the classes of the gate client) ----------

class ApprovalTypeError(_gc.TokenError):
    """`authorization_details[0].type` is not the action the application is about to carry out."""
    kind = "approval_type"


class ApprovalFieldsError(_gc.TokenError):
    """The fields of the entry differ from the action the application stored (a name, a type or a value)."""
    kind = "approval_fields"


class SubjectError(_gc.TokenError):
    """`sub` is not the account the application acts for."""
    kind = "subject"


class NonceError(_gc.TokenError):
    """`nonce` is not the `state` the application keeps in the person's session (browser entry)."""
    kind = "nonce"


class ReplayError(_gc.TokenError):
    """The `jti` was seen before: this confirmation was used already."""
    kind = "replay"


# ---------- the canonical form (RFC 8785 for the values of a confirmation) ----------

def canonical(entry: Any) -> str:
    """RFC 8785 (JCS) for what an `authorization_details` entry holds — an object with ASCII member names whose values
    are strings, integers within ±(2^53 − 1) and booleans: members sorted, no whitespace, strings in UTF-8 with only
    `"` and `\\` escaped (TinySesam refuses control characters in field values, so the other escapes of JCS never
    occur). Python's `json` writes exactly that for these values."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_digest(entry: Any) -> str:
    """`ts_payload_sha256`: SHA-256 over the canonical form of the entry, base64url without padding."""
    return _gc._b64u_encode(hashlib.sha256(canonical(entry).encode("utf-8")).digest())


# ---------- issuing (TinySesam) ----------

def issue(private, *, iss: str, aud: str, sub: str, jti: str, entry: dict, auth_time: int, amr: list, act: str,
          now: int, ttl: int, nonce: Optional[str] = None) -> str:
    """A confirmation (JWS Compact, `EdDSA`) for ONE action: `entry` is the stored `{"type": …, <fields>}`, `act` the
    requesting application's id, `ttl` at most `MAX_LIFETIME`. Called by TinySesam when the application picks it up —
    nowhere else, so the token exists only in that one answer."""
    from . import gate as _gate
    if not 0 < int(ttl) <= MAX_LIFETIME:
        raise ValueError(f"ttl {ttl}: 1 to {MAX_LIFETIME} seconds")
    head = {"alg": _ALGORITHM, "typ": TOKEN_TYPE, "kid": _gate.key_name_id(_gate.public_raw(private))}
    body: dict = {"iss": iss, "aud": aud, "sub": str(sub), "iat": int(now), "nbf": int(now), "exp": int(now) + int(ttl),
                  "jti": jti, "auth_time": int(auth_time), "amr": list(amr), "act": {"sub": f"app:{act}"},
                  "authorization_details": [dict(entry)], "ts_payload_sha256": payload_digest(entry)}
    if nonce:
        body["nonce"] = nonce
    signing = (_gc._b64u_encode(json.dumps(head, separators=(",", ":")).encode("ascii")) + "."
               + _gc._b64u_encode(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
    return signing + "." + _gc._b64u_encode(private.sign(signing.encode("ascii")))


# ---------- the reference check (an application) ----------
#
# Steps 1–8 are those of the gate client (spec/gate-client.md §4.4) with this module's `typ` and the APPROVAL key set.

def _check_typ(head: dict) -> None:
    typ = head.get("typ")
    if not (isinstance(typ, str) and typ.isascii() and typ.lower() == TOKEN_TYPE):
        raise _gc.HeaderError("typ")


def _check_header_members(head: dict) -> None:
    if set(head) - _HEADER_MEMBERS:
        raise _gc.HeaderError("a header member besides alg, typ and kid")


def _check_alg(head: dict) -> None:
    if head.get("alg") != _ALGORITHM or not isinstance(head.get("alg"), str):
        raise _gc.HeaderError("alg is not EdDSA")


def _parse(jws: Any) -> "_gc._Parsed":
    """Steps 1–5."""
    if not isinstance(jws, str):
        raise _gc.MalformedToken("not a string")
    _gc._check_size(jws)
    h_seg, p_seg, s_seg = _gc._split(jws)
    head_raw, payload, signature = _gc._b64u_decode(h_seg), _gc._b64u_decode(p_seg), _gc._b64u_decode(s_seg)
    head = _gc._json_object(head_raw)
    _check_header_members(head)
    _check_alg(head)
    _check_typ(head)
    kid = _gc._check_kid(head)
    _gc._check_signature_length(head, signature, kid)
    return _gc._Parsed(head=head, kid=kid, signing_input=f"{h_seg}.{p_seg}".encode("ascii"), payload=payload,
                       signature=signature)


def _select_key(parsed, keys: Mapping[str, bytes]) -> bytes:
    """Step 6: the key from the APPROVAL key set of the configuration, never from the token or the gate set."""
    public = keys.get(parsed.kid)
    if public is None:
        raise _gc.KidError("not in the key set", kid=parsed.kid)
    return public


def _verify_signature(parsed, public: bytes) -> None:
    """Step 7."""
    _gc._verify_signature(parsed, public)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _gc._MAX_SAFE_INTEGER


def _is_value(value: Any) -> bool:
    """A field value of an entry: a string, an integer within ±(2^53 − 1), a boolean — nothing else."""
    if isinstance(value, bool) or isinstance(value, str):
        return True
    return isinstance(value, int) and -_gc._MAX_SAFE_INTEGER <= value <= _gc._MAX_SAFE_INTEGER


def _text(value: Any, limit: int = _MAX_TEXT) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and not _gc._has_control(value)


def _check_present(claims: dict) -> None:
    for name in _REQUIRED:
        if name not in claims:
            raise _gc.ClaimsError(f"{name} missing")


def _check_claim_types(claims: dict) -> None:
    if not isinstance(claims["iss"], str):
        raise _gc.ClaimsError("iss")
    if not _text(claims["sub"], 1000):
        raise _gc.ClaimsError("sub")
    for name in ("iat", "nbf", "exp", "auth_time"):
        if not _is_int(claims[name]):
            raise _gc.ClaimsError(name)
    if not _text(claims["jti"]):
        raise _gc.ClaimsError("jti")
    amr = claims["amr"]
    if not (isinstance(amr, list) and amr and all(_text(a, 32) for a in amr)):
        raise _gc.ClaimsError("amr")
    act = claims["act"]
    if not (isinstance(act, dict) and _text(act.get("sub"))):
        raise _gc.ClaimsError("act")
    if not isinstance(claims["ts_payload_sha256"], str):
        raise _gc.ClaimsError("ts_payload_sha256")
    if "nonce" in claims and not _text(claims["nonce"]):
        raise _gc.ClaimsError("nonce")


def _check_audience_type(claims: dict) -> None:
    """`aud` is ONE string (the application's id), never an array — an array could name several applications."""
    if not isinstance(claims["aud"], str):
        raise _gc.ClaimsError("aud is not a string")


def _check_details(claims: dict) -> dict:
    """`authorization_details` is an array with exactly one object: a string `type` and field values of the allowed
    types. Returns the entry."""
    details = claims["authorization_details"]
    if not isinstance(details, list) or len(details) != 1:
        raise _gc.ClaimsError("authorization_details is not one entry")
    entry = details[0]
    if not isinstance(entry, dict) or not _text(entry.get("type"), 100):
        raise _gc.ClaimsError("authorization_details[0]")
    if not all(_is_value(v) for v in entry.values()):
        raise _gc.ClaimsError("a field value of an unsupported type")
    return entry


def _check_digest(claims: dict, entry: dict) -> None:
    """`ts_payload_sha256` is the digest of exactly this entry."""
    if claims["ts_payload_sha256"] != payload_digest(entry):
        raise _gc.ClaimsError("ts_payload_sha256 does not match the entry")


def _check_order(claims: dict) -> None:
    """`iat` not later than `nbf`, the step-up not later than the issuing."""
    if claims["iat"] > claims["nbf"] or claims["auth_time"] > claims["iat"]:
        raise _gc.ClaimsError("iat, nbf and auth_time out of order")


def _check_issuer(claims: dict, issuer: str) -> None:
    if claims["iss"] != issuer:
        raise _gc.IssuerError()


def _check_audience(claims: dict, app_id: str) -> None:
    if claims["aud"] != app_id:
        raise _gc.AudienceError()


def _check_lifetime(claims: dict) -> None:
    if claims["exp"] <= claims["nbf"] or claims["exp"] - claims["nbf"] > MAX_LIFETIME:
        raise _gc.LifetimeError()


def _check_not_before(claims: dict, now: int, leeway: int) -> None:
    if claims["nbf"] > now + leeway:
        raise _gc.NotYetValid()


def _check_expiry(claims: dict, now: int, leeway: int) -> None:
    if claims["exp"] + leeway <= now:
        raise _gc.Expired()


def _check_type(entry: dict, expect_type: str) -> None:
    if entry["type"] != expect_type:
        raise ApprovalTypeError()


def _same(a: Any, b: Any) -> bool:
    """Equal value AND equal JSON type — `1`, `1.0`, `true` and `"1"` are four different values."""
    return type(a) is type(b) and a == b


def _check_fields(entry: dict, expect_fields: Mapping[str, Any]) -> None:
    got = {k: v for k, v in entry.items() if k != "type"}
    if set(got) != set(expect_fields) or not all(_same(got[k], expect_fields[k]) for k in got):
        raise ApprovalFieldsError()


def _check_subject(claims: dict, expect_sub: str) -> None:
    if claims["sub"] != expect_sub:
        raise SubjectError()


def _check_nonce(claims: dict, expect_nonce: Optional[str]) -> None:
    if expect_nonce is not None and claims.get("nonce") != expect_nonce:
        raise NonceError()


def _remember(jti_store: Callable[[str, int], bool], jti: str, until: int) -> None:
    """Step 12, after every other check: the `jti` written atomically into the application's own store (an INSERT with
    a unique key), kept until `until`. False — seen before — is a replay."""
    if jti_store(jti, until) is not True:
        raise ReplayError()


def _check_leeway(leeway: Any) -> int:
    if not isinstance(leeway, int) or isinstance(leeway, bool) or not 0 <= leeway <= MAX_LEEWAY:
        raise ConfigError(f"leeway must be an integer from 0 to {MAX_LEEWAY} seconds")
    return leeway


def key_set(keys: Any) -> dict:
    """kid → public key from a JWKS document (`/auth/approvals/jwks.json`, rules of spec/gate-client.md §4.3) or from
    an existing mapping kid → 32 raw bytes."""
    if isinstance(keys, Mapping) and "keys" not in keys:
        out = {}
        for kid, public in keys.items():
            if not (isinstance(public, bytes) and len(public) == 32 and kid == _gc._key_id(public)):
                raise ConfigError("keys: kid → the 32 raw bytes of an Ed25519 public key, kid as in spec §4.1")
            out[kid] = public
        return out
    try:
        return _gc._parse_jwks(keys)
    except _gc.GateError as e:
        raise ConfigError("keys: not a usable JWKS document") from e


def verify(token: Any, *, keys: Any, issuer: str, app_id: str, expect_type: str, expect_fields: Mapping[str, Any],
           expect_sub: str, jti_store: Callable[[str, int], bool], expect_nonce: Optional[str] = None,
           now: Optional[int] = None, leeway: int = 0) -> dict:
    """Check a confirmation before carrying the action out — the claims, or a `gate_client.TokenError` whose `kind` is
    the class of spec/approval-token.md §5. Every class means: do not carry the action out.

    `keys` is the APPROVAL key set (a JWKS document or kid → raw bytes), never the gate key set; `issuer` TinySesam's
    `base_url` without a trailing slash; `app_id` the application's own id; `expect_type` and `expect_fields` the action
    the application stored when it asked (exactly — names, JSON types and values); `expect_sub` the account it acts
    for; `expect_nonce` the `state` it kept in the session (browser entry; None when it sent none); `jti_store(jti,
    until)` stores the id atomically and answers True only the first time. Run the application's own rules again
    (still the owner? does the thing still exist?) after this, then carry the action out."""
    import time
    lookup = key_set(keys)
    leeway = _check_leeway(leeway)
    when = int(time.time()) if now is None else int(now)
    parsed = _parse(token)
    public = _select_key(parsed, lookup)
    _verify_signature(parsed, public)
    try:
        claims = _gc._json_object(parsed.payload)           # step 8 — only after the signature
        _check_present(claims)                              # step 9
        _check_claim_types(claims)
        _check_audience_type(claims)
        entry = _check_details(claims)
        _check_digest(claims, entry)
        _check_order(claims)
        _check_issuer(claims, issuer)                       # step 10
        _check_audience(claims, app_id)
        _check_lifetime(claims)
        _check_not_before(claims, when, leeway)
        _check_expiry(claims, when, leeway)
        _check_type(entry, expect_type)                     # step 11
        _check_fields(entry, expect_fields)
        _check_subject(claims, expect_sub)
        _check_nonce(claims, expect_nonce)
        _remember(jti_store, claims["jti"], claims["exp"] + leeway)   # step 12
    except _gc.GateError as e:
        e.kid = parsed.kid
        raise
    return claims

