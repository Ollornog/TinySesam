"""Relaxations of `tinysesam.approval_token.verify` for the self-probes of `tests/test_approval_vectors.py`.

Every check of the reference is a small module-level function. A relaxation replaces exactly one rule with a lenient
version inside `relaxed(name)` — two functions only where they are one rule (`aud` is ONE string: its type and its
comparison). The vector suite shows with them that every rule is measured by at least one vector, and that every
attack vector carries one defect. They live here, in the tests, and never in the package.
"""
from __future__ import annotations

import contextlib
import importlib.util
import os

from tinysesam import approval_token as at
from tinysesam import gate_client as gc

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _gate_key_a() -> tuple[str, bytes]:
    spec = importlib.util.spec_from_file_location("_gate_vectors", os.path.join(_ROOT, "scripts", "_gate_vectors.py"))
    gv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gv)
    return gv.kid("A"), gv._public("A")


def _attacker_x() -> tuple[str, bytes]:
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tinysesam import gate
    seed = hashlib.sha256(b"tinysesam approval test vector key X").digest()
    public = gate.public_raw(Ed25519PrivateKey.from_private_bytes(seed))
    return gate.key_name_id(public), public


def _also_knows(extra):
    def select(parsed, keys):
        kid, public = extra()
        return public if parsed.kid == kid else _ORIGINAL["_select_key"](parsed, keys)
    return select


def _details_lenient(claims):
    details = claims["authorization_details"]
    entry = details if isinstance(details, dict) else details[0] if isinstance(details, list) and details else None
    if not isinstance(entry, dict) or not isinstance(entry.get("type"), str):
        raise gc.ClaimsError("authorization_details[0]")
    return entry


def _aud_lenient(claims, app_id):
    aud = claims["aud"]
    if app_id not in (aud if isinstance(aud, list) else [aud]):
        raise gc.AudienceError()


def _types_lenient(claims):
    return None


def _noop(*_a, **_k):
    return None


def _never_seen(jti_store, jti, until):
    return None


#: name → {function of `approval_token`: replacement}
RELAXATIONS = {
    "typ": {"_check_typ": _noop},
    "alg": {"_check_alg": _noop},
    "header_members": {"_check_header_members": _noop},
    "gate_keys_trusted": {"_select_key": _also_knows(_gate_key_a)},
    "attacker_key_trusted": {"_select_key": _also_knows(_attacker_x)},
    "aud_array": {"_check_audience_type": _noop, "_check_audience": _aud_lenient},
    "details_shape": {"_check_details": _details_lenient},
    "digest": {"_check_digest": _noop},
    "claim_types": {"_check_claim_types": _types_lenient},
    "order": {"_check_order": _noop},
    "issuer": {"_check_issuer": _noop},
    "audience": {"_check_audience": _noop},
    "lifetime": {"_check_lifetime": _noop},
    "not_before": {"_check_not_before": _noop},
    "expiry": {"_check_expiry": _noop},
    "type": {"_check_type": _noop},
    "fields": {"_check_fields": _noop},
    "subject": {"_check_subject": _noop},
    "nonce": {"_check_nonce": _noop},
    "replay": {"_remember": _never_seen},
}

_ORIGINAL = {name: getattr(at, name) for patch in RELAXATIONS.values() for name in patch}


@contextlib.contextmanager
def relaxed(name: str):
    patch = RELAXATIONS[name]
    try:
        for fn, replacement in patch.items():
            setattr(at, fn, replacement)
        yield
    finally:
        for fn in patch:
            setattr(at, fn, _ORIGINAL[fn])
