"""Relaxations of `tinysesam.gate_client` for the self-probes of `tests/test_gate_vectors.py`.

Every check of the client is a small module-level function or constant. A relaxation replaces exactly one of them
(two only where they are one defect, such as the signature's length and its verification) with a lenient version,
inside `relaxed(name)`. The vector suite shows with them that every rule is measured by at least one vector, and that
every attack vector carries one defect. They live here, in the tests, and never in the package.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac

from tinysesam import gate_client as gc


def _lenient_b64(segment):
    bare = "".join(segment.split()).replace("=", "")
    try:
        return base64.urlsafe_b64decode(bare + "=" * (-len(bare) % 4))
    except ValueError as e:
        raise gc.MalformedToken("base64") from e


def _header_alg(head):
    alg = head.get("alg")
    return alg.lower() if isinstance(alg, str) and alg.lower() in ("none", "hs256") else "eddsa"


def _alg_length(head, signature, kid):
    if _header_alg(head) == "eddsa" and len(signature) != 64:
        raise gc.SignatureError("not 64 bytes")


def _alg_verify(original):
    def verify(parsed, public):
        alg = _header_alg(parsed.head)
        if alg == "none":
            return
        if alg == "hs256":
            for secret in (public, base64.b64encode(public)):
                if hmac.compare_digest(hmac.new(secret, parsed.signing_input, hashlib.sha256).digest(),
                                       parsed.signature):
                    return
            raise gc.SignatureError("HMAC")
        original(parsed, public)
    return verify


def _embedded_select(original):
    def select(parsed, lookup):
        jwk = parsed.head.get("jwk")
        if isinstance(jwk, dict):
            return _lenient_b64(str(jwk.get("x")))
        return original(parsed, lookup)
    return select


def _embedded_members(head):
    if set(head) - gc._HEADER_MEMBERS - {"jwk"}:
        raise gc.HeaderError("member")


def _loose_types(claims):
    """Only what the later steps need: time claims that `int()` accepts, converted in place."""
    for name in ("iat", "nbf", "exp"):
        try:
            claims[name] = int(claims[name])
        except (KeyError, TypeError, ValueError) as e:
            raise gc.ClaimsError(name) from e
    claims.setdefault("iss", None)
    claims.setdefault("aud", None)
    claims["sub"] = str(claims.get("sub"))


def _loose_iat(claims):
    return None


def _strip_controls(text):
    return "".join(c for c in text if not gc._has_control(c))


def _first_value(pairs, wanted):
    want = {w.lower() for w in wanted}
    out = {}
    for name, value in pairs:
        key = gc._field_name(name)
        if key not in want or key in out:
            continue
        out[key] = gc._octets(value[0] if isinstance(value, list) else value)
    return out


def _any_jwk(entry):
    if not isinstance(entry, dict):
        return None
    try:
        return str(entry.get("kid")), _lenient_b64(str(entry.get("x")))
    except gc.GateError:
        return None


def _aud_casefold(aud, want):
    if not any(str(a).lower() == want.lower() for a in (aud if isinstance(aud, list) else [aud])):
        raise gc.AudienceError()


def _iss_prefix(iss, want):
    if not str(iss).startswith(want):
        raise gc.IssuerError()


def _any_kid(head):
    if not isinstance(head.get("kid"), str):
        raise gc.KidError("kid missing")
    return head["kid"]


def _nothing(*_args, **_kwargs):
    return None


def _kind_casefold(kind, error):
    if isinstance(kind, str) and kind.lower() in gc._ACCOUNT_KINDS:
        return kind.lower()
    raise error("kind")


#: name -> {attribute of gate_client: replacement, or a function of the original returning the replacement}
RELAXATIONS = {
    "alg_from_header": {"_check_alg": _nothing, "_check_signature_length": _alg_length,
                        "_verify_signature": _alg_verify},
    "ignore_typ": {"_check_typ": _nothing},
    "embedded_jwk": {"_check_header_members": _embedded_members, "_select_key": _embedded_select},
    "unknown_header_members": {"_check_header_members": _nothing},
    "no_duplicate_check": {"_unique_pairs": dict},
    "lenient_base64": {"_b64u_decode": _lenient_b64},
    "lenient_utf8": {"_decode_utf8": lambda raw: raw.decode("utf-8", "replace")},
    "allow_bom": {"_check_bom": lambda text: text.removeprefix("\ufeff")},
    "allow_nan": {"_json_constant": float},
    "no_size_limit": {"_MAX_TOKEN_BYTES": 10 ** 9},
    "skip_signature": {"_check_signature_length": _nothing, "_verify_signature": _nothing},
    "no_exp": {"_check_expiry": _nothing},
    "no_nbf": {"_check_not_before": _nothing},
    "no_lifetime": {"_check_lifetime": _nothing},
    "no_control_check": {"_check_claim_controls": _nothing},
    "no_ts_id_check": {"_check_ts_id": _nothing},
    "allow_empty_sub": {"_check_sub": _nothing},
    "aud_casefold": {"_check_audience": _aud_casefold},
    "iss_prefix": {"_check_issuer": _iss_prefix},
    "kid_any_format": {"_check_kid": _any_kid},
    "claim_types_loose": {"_check_claim_types": _loose_types, "_check_iat": _loose_iat},
    "jwks_any_entry": {"_jwk_entry": _any_jwk},
    "jwks_no_interval": {"_JWKS_MIN_INTERVAL": 0},
    "jwks_no_stale_limit": {"_JWKS_STALE_MAX": 10 ** 12},
    "header_strip_control": {"_check_header_controls": _strip_controls},
    "header_first_value": {"_collect": _first_value},
    "header_lenient_utf8": {"_decode_header": lambda raw: raw.decode("utf-8", "replace")},
    "header_any_id": {"_check_remote_id": _nothing},
    "remote_auth_empty_is_session": {"_kind_of": lambda auth: "session" if auth in ("session", "") else "token"},
    "kind_missing_is_user": {"_check_kind_present": lambda kind, error: "user" if kind in (None, "") else kind},
    "kind_casefold": {"_check_kind_value": _kind_casefold},
    "kind_any_value": {"_check_kind_value": lambda kind, error: kind},
    "kind_no_consistency": {"_check_kind_consistent": _nothing},
    "groups_no_trim": {"_trim_group": lambda part: part},
    "topbar_any_href": {"_safe_href": lambda href: isinstance(href, str)},
}

#: Replacements that are built from the original function (wrappers).
_WRAPPERS = {_alg_verify, _embedded_select}


@contextlib.contextmanager
def relaxed(*names):
    """Switch off the named checks of `tinysesam.gate_client` for the duration of the block."""
    saved = {}
    try:
        for name in names:
            for attribute, replacement in RELAXATIONS[name].items():
                original = getattr(gc, attribute)
                saved.setdefault(attribute, original)
                setattr(gc, attribute, replacement(original) if replacement in _WRAPPERS else replacement)
        yield
    finally:
        for attribute, original in saved.items():
            setattr(gc, attribute, original)


def snapshot():
    """Every patchable attribute, to prove that `relaxed` restores the module."""
    return {a: getattr(gc, a) for spec in RELAXATIONS.values() for a in spec}

