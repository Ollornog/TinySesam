#!/usr/bin/env python3
"""Generate the language-neutral approval confirmation vectors `spec/vectors/approval.json` from the real TinySesam code.

    python scripts/_approval_vectors.py           # write spec/vectors/approval.json
    python scripts/_approval_vectors.py --check   # exit 1 when the file differs from what the code generates now

The valid confirmations come from TinySesam's own path: a probe installation (approval key `P` from its key file)
holds confirmed application actions, and `Approvals.pickup` — the transition `approved` → `consumed` and
`approval_token.issue` — hands them out under a fixed clock. The attacks are built here from those claims, byte by
byte, and signed with fixed test keys; a real gate token (key `A` of `spec/vectors/keys.json`, from
`scripts/_gate_vectors.py`) is one of them. The expected verdict of every vector is written down here by hand, never
computed by a verifier. `tests/test_approval_vectors.py` checks the file against this generator and the Python
reference `tinysesam.approval_token.verify`, and that every attack vector carries exactly one defect.

The keys are TEST MATERIAL: derived from a public label, printed in the file, worthless as a secret.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "spec", "vectors", "approval.json")

FORMAT = 1                 # spec/approval-token.md, version 1
NOW = 1767225600           # 2026-01-01T00:00:00Z — the pickup (iat = nbf)
ISSUER = "https://auth.example.com"
APP_ID = "example"
TTL = 120
STEP_UP = NOW - 40         # auth_time: the person confirmed 40 s before the pickup
DELETE = "example.collection.delete_permanently"
QUOTA = "example.member.set_quota"

_spec = importlib.util.spec_from_file_location("_gate_vectors", os.path.join(ROOT, "scripts", "_gate_vectors.py"))
gv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gv)

TYPES = {
    DELETE: {"fields": {"collection": {"type": "string", "max": 64, "pattern": "^[A-Za-z0-9_-]{1,64}$"},
                        "name": {"type": "string", "max": 120}},
             "title": {"en": "Delete collection permanently", "de": "Collection endgültig löschen"},
             "summary": {"en": "Permanently delete the collection {name} ({collection}). This cannot be undone.",
                         "de": "Die Collection {name} ({collection}) endgültig löschen. Das lässt sich nicht "
                               "rückgängig machen."},
             "irreversible": True},
    QUOTA: {"fields": {"member": {"type": "string", "max": 200}, "quota": {"type": "integer", "min": -1, "max": 10 ** 6},
                       "notify": {"type": "boolean"}},
            "title": {"en": "Set a member's quota", "de": "Kontingent eines Mitglieds setzen"},
            "summary": {"en": "Set the quota of {member} to {quota} (notify: {notify}).",
                        "de": "Das Kontingent von {member} auf {quota} setzen (benachrichtigen: {notify})."}},
}


# ---------- test keys ----------

def _seed(label: str) -> bytes:
    return hashlib.sha256(b"tinysesam approval test vector key " + label.encode("ascii")).digest()


def _private(label: str):
    """`P` active and `Q` previous approval key of the probe, `X` the attacker's; `A` is the GATE test key."""
    if label == "A":
        return gv._private("A")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(_seed(label))


def _public(label: str) -> bytes:
    from tinysesam import gate
    return gate.public_raw(_private(label))


def kid(label: str) -> str:
    from tinysesam import gate
    return gate.key_name_id(_public(label))


def jwk(label: str) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": gv.b64u(_public(label)), "kid": kid(label), "alg": "EdDSA",
            "use": "sig"}


def jwks(*labels: str) -> dict:
    return {"keys": [jwk(lb) for lb in labels]}


def head(label: str = "P", **change) -> dict:
    h = {"alg": "EdDSA", "typ": "tinysesam-approval+jwt", "kid": kid(label)}
    for k, v in change.items():
        if v is None:
            h.pop(k, None)
        else:
            h[k] = v
    return h


def signed(h, payload, signer: str = "P") -> str:
    hs = gv.b64u(h if isinstance(h, bytes) else gv.enc(h))
    ps = gv.b64u(payload if isinstance(payload, bytes) else gv.enc(payload))
    return f"{hs}.{ps}." + gv.b64u(_private(signer).sign(f"{hs}.{ps}".encode("ascii")))


def digest_of(text: str) -> str:
    return gv.b64u(hashlib.sha256(text.encode("utf-8")).digest())


# ---------- the probe installation ----------

class Probe:
    """A throwaway TinySesam with `P` as its approval key (and `Q` as the previous one), the application `example` with
    the two types above, and the person `anna` who confirms."""

    def __init__(self):
        from tinysesam import TinySesam, TinySesamConfig
        self.dir = tempfile.mkdtemp(prefix="tinysesam-approval-vectors-")
        key_file = os.path.join(self.dir, "approval.key")
        with open(key_file, "w", encoding="ascii") as f:
            f.write(base64.b64encode(_seed("P")).decode("ascii") + "\n")
            f.write(base64.b64encode(_seed("Q")).decode("ascii") + f" since={NOW - 60}\n")
        os.chmod(key_file, 0o600)
        with open(os.devnull, "w") as quiet, contextlib.redirect_stderr(quiet):
            self.auth = TinySesam(TinySesamConfig(
                db_path=os.path.join(self.dir, "probe.db"), base_url=ISSUER, approvals_enabled=True,
                apikey_enabled=True, passkey_enabled=False, oidc_enabled=False, approval_key_file=key_file,
                approval_token_ttl_sec=TTL,
                apps={APP_ID: {"account": "svc-example", "name": {"en": "Example"},
                               "approvals": {"types": TYPES,
                                             "return_urls": ["https://app.example.com/approvals/return"]}}}))
        a = self.auth
        self.service = a.create_service("svc-example")
        self.anna = a.create_user("anna", None, display_name="Anna Berg")
        assert a.approval_jwks()["keys"][0]["kid"] == kid("P"), "the probe does not sign with key P"
        self.count = 0

    def close(self) -> None:
        import shutil
        self.auth.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def confirmation(self, type_: str, fields: dict, nonce=None, signer: str = "P") -> str:
        """The confirmation exactly as `GET /auth/api/approvals/{id}` hands it out after the person confirmed."""
        from tinysesam import approvals as apv
        from tinysesam import keys as K
        a = self.auth
        self.count += 1
        approval_id = "apv_" + base64.b32encode(hashlib.sha256(f"vector {self.count}".encode()).digest()[:16]
                                                ).decode("ascii").rstrip("=").lower()
        text = apv.canonical({"type": type_, **apv.validate_fields(a._approvals().app_approvals()[APP_ID]["types"]
                                                                   [type_], fields)})
        a.store.add_approval({
            "id": approval_id, "class": "app", "type": type_, "app_id": APP_ID, "subject_id": int(self.anna),
            "requester_kind": "app", "requester_ref": str(int(self.service)), "payload": text,
            "payload_hash": apv.payload_hash(text), "match_code": "418 207",
            "return_url": "https://app.example.com/approvals/return" if nonce else None, "nonce": nonce,
            "state": "approved", "created_at": STEP_UP - 20, "expires_at": NOW + 300, "decided_at": STEP_UP,
            "stepup_amr": json.dumps(["hwk", "user"]), "auth_time": STEP_UP})
        ring = a._approval_ring()
        old_now, old_ring = apv._now, a._approval_keyring
        apv._now = lambda: NOW
        if signer == "Q":
            a._approval_keyring = K.Keyring(K.APPROVAL, [ring.keys[1], ring.keys[0]], ring.origin)
        try:
            out = a._approvals().pickup(a.store.get_approval(approval_id))
        finally:
            apv._now, a._approval_keyring = old_now, old_ring
        assert out["state"] == "consumed" and "confirmation" in out, out
        return out["confirmation"]


# ---------- vectors ----------

def vectors(p: Probe) -> list:
    out: list = []
    fields = {"collection": "c_81f2", "name": "Project Alpha"}
    expect = {"type": DELETE, "fields": fields, "sub": str(p.anna)}

    def add(id_, reason, jws, expected, *, attack=None, now=NOW, leeway=0, keys=("P", "Q"), exp=None, seen=()):
        e = copy.deepcopy(exp if exp is not None else expect)
        out.append({"id": id_, "reason": reason, "attack": attack,
                    "input": {"jws": jws, "now": now, "leeway": leeway, "issuer": ISSUER, "app_id": APP_ID,
                              "jwks": jwks(*keys), "expect": e, "seen": list(seen)},
                    "expected": expected})

    def ok(jws):
        return {"ok": True, "claims": gv.claims_of(jws)}

    def err(cls):
        return {"ok": False, "error": cls}

    good = p.confirmation(DELETE, fields)
    base = gv.claims_of(good)

    def change(**kw) -> dict:
        c = copy.deepcopy(base)
        for k, v in kw.items():
            if v is None:
                c.pop(k, None)
            else:
                c[k] = v
        return c

    def with_entry(entry: dict, **kw) -> dict:
        from tinysesam import approval_token
        return change(authorization_details=[entry], ts_payload_sha256=approval_token.payload_digest(entry), **kw)

    # --- valid ---
    add("valid-basic", "A confirmation as TinySesam hands it out: key P, one entry, nothing else to it.", good, ok(good))
    with_nonce = p.confirmation(DELETE, fields, nonce="k3J-browser.entry_7~")
    add("valid-nonce", "Browser entry: the application's state comes back as `nonce` and matches the session.",
        with_nonce, ok(with_nonce), exp=dict(expect, nonce="k3J-browser.entry_7~"))
    add("valid-nonce-not-expected", "A `nonce` the application did not ask to compare is no reason to refuse.",
        with_nonce, ok(with_nonce))
    previous = p.confirmation(DELETE, fields, signer="Q")
    add("valid-previous-key", "Signed with the previous key Q right after a rotation; the key set still holds it.",
        previous, ok(previous))
    mixed_fields = {"member": "Jürgen \"JJ\" Müller \\ 東京 🚀", "quota": -1, "notify": False}
    mixed = p.confirmation(QUOTA, mixed_fields)
    add("valid-escapes-int-bool", "Quote, backslash, umlaut, CJK and emoji in a string, a negative integer, a "
                                  "boolean: the digest is over the RFC 8785 form (only `\"` and `\\` escaped).",
        mixed, ok(mixed), exp={"type": QUOTA, "fields": mixed_fields, "sub": str(p.anna)})
    add("valid-leeway-edge", "One second before `exp + leeway` with a leeway of 30 s.", good, ok(good),
        now=base["exp"] + 29, leeway=30)
    add("valid-not-before-leeway", "Thirty seconds before `nbf` with a leeway of 30 s.", good, ok(good),
        now=base["nbf"] - 30, leeway=30)

    # --- header ---
    add("typ-gate", "A confirmation that calls itself a gate token: `typ` is tinysesam-gate+jwt.",
        signed(head(typ="tinysesam-gate+jwt"), base), err("header"), attack="typ-wrong")
    add("typ-missing", "No `typ` at all: a plain JWT is no confirmation.", signed(head(typ=None), base), err("header"),
        attack="typ-wrong")
    add("typ-application-prefix", "`application/tinysesam-approval+jwt`: the type is compared without prefix.",
        signed(head(typ="application/tinysesam-approval+jwt"), base), err("header"), attack="typ-wrong")
    add("alg-wrong", "`alg` ES256 over an Ed25519 signature: the algorithm is the checker's constant.",
        signed(head(alg="ES256"), base), err("header"), attack="alg-wrong")
    add("header-jku", "A `jku` in the header: never a key from the token.",
        signed(head(jku="https://evil.example/jwks.json"), base), err("header"), attack="embedded-key")
    gate_token = gv.issue("A", sub=str(p.anna), claims={"user": "anna", "kind": "user", "auth": "session"},
                          aud=APP_ID, iss=ISSUER, now=NOW, ttl=TTL, jti="gate")
    add("gate-token", "A real gate token (gate key A, typ tinysesam-gate+jwt) presented as a confirmation.",
        gate_token, err("header"), attack="gate-token")

    # --- keys ---
    add("gate-key", "A well-formed confirmation signed with the GATE key A under its own kid: not in the approval key "
                    "set — a checker that also trusts the gate keys would accept it.",
        signed(head("A"), base, signer="A"), err("kid"), attack="gate-key")
    add("foreign-key", "Signed with the attacker's key X under its own kid.", signed(head("X"), base, signer="X"),
        err("kid"), attack="foreign-key")
    add("foreign-key-trusted-kid", "Signed with X under the kid of P.", signed(head("P"), base, signer="X"),
        err("signature"), attack="foreign-key")
    add("kid-retired", "Signed with Q after Q left the key set.", previous, err("kid"), keys=("P",),
        attack="foreign-key")
    tampered = good.split(".")
    tampered[1] = gv.b64u(gv.enc(change(sub="1")))
    add("payload-changed", "The payload changed after signing (`sub` swapped).", ".".join(tampered), err("signature"),
        attack="bad-signature")

    # --- claims ---
    add("aud-array", "`aud` as an array that holds the application's id: a confirmation names ONE application.",
        signed(head(), change(aud=[APP_ID])), err("claims"), attack="aud-array")
    add("details-two", "Two `authorization_details` entries: a confirmation carries exactly one action.",
        signed(head(), change(authorization_details=base["authorization_details"] * 2)), err("claims"),
        attack="details-count")
    add("details-empty", "An empty `authorization_details` array.", signed(head(), change(authorization_details=[])),
        err("claims"), attack="details-count")
    add("details-object", "`authorization_details` as an object instead of an array of one.",
        signed(head(), change(authorization_details=base["authorization_details"][0])), err("claims"),
        attack="details-count")
    add("hash-other-entry", "`ts_payload_sha256` of another entry (the name changed).",
        signed(head(), change(ts_payload_sha256=digest_of(json.dumps(dict(base["authorization_details"][0],
                                                                         name="Project Beta"),
                                                                    sort_keys=True, separators=(",", ":"))))),
        err("claims"), attack="hash-mismatch")
    add("hash-not-canonical", "The digest over the entry with spaces and unsorted members instead of RFC 8785.",
        signed(head(), change(ts_payload_sha256=digest_of(json.dumps(base["authorization_details"][0])))),
        err("claims"), attack="hash-mismatch")
    add("auth-time-after-iat", "The step-up after the issuing: impossible for TinySesam.",
        signed(head(), change(auth_time=NOW + 5)), err("claims"), attack="claim-types")
    add("amr-not-array", "`amr` as a string.", signed(head(), change(amr="hwk")), err("claims"), attack="claim-types")
    add("auth-time-missing", "No `auth_time`: when the person confirmed is part of the confirmation.",
        signed(head(), change(auth_time=None)), err("claims"), attack="claim-types")
    add("act-missing", "No `act`: who asked is part of the confirmation.", signed(head(), change(act=None)),
        err("claims"), attack="claim-types")
    add("jti-missing", "No `jti`: without it the application cannot refuse a second use.",
        signed(head(), change(jti=None)), err("claims"), attack="claim-types")
    add("sub-control", "A line feed in `sub` — refused as such, even where the application expects that value.",
        signed(head(), change(sub=str(p.anna) + "\n")), err("claims"), exp=dict(expect, sub=str(p.anna) + "\n"),
        attack="unicode-control")
    add("field-object", "A field value of an unsupported type (an object).",
        signed(head(), with_entry(dict(base["authorization_details"][0], name={"x": 1}))), err("claims"),
        attack="claim-types")

    # --- values ---
    add("issuer-slash", "`iss` with a trailing slash.", signed(head(), change(iss=ISSUER + "/")), err("issuer"),
        attack="issuer")
    add("aud-other-channel", "Confirmed for `example_test`, presented to `example`: a test channel never counts in "
                             "the stable one.", signed(head(), change(aud="example_test")), err("audience"),
        attack="audience")
    add("lifetime-301", "`exp - nbf` = 301 s: above the 300 s a confirmation may live.",
        signed(head(), change(exp=base["nbf"] + 301)), err("lifetime"), attack="lifetime")
    add("expired-at-exp", "Checked at `exp` exactly.", good, err("expired"), now=base["exp"], attack="expired")
    add("expired-leeway-edge", "At `exp + leeway` exactly, leeway 30 s.", good, err("expired"), now=base["exp"] + 30,
        leeway=30, attack="expired")
    add("not-yet-valid", "One second before `nbf`, no leeway.", good, err("not_yet_valid"), now=base["nbf"] - 1,
        attack="not-yet-valid")

    # --- binding to the stored action ---
    add("type-other-action", "Confirmed `…delete_permanently`, presented for `…archive`.", good, err("approval_type"),
        exp=dict(expect, type="example.collection.archive"), attack="type-mismatch")
    add("field-value-differs", "The application stored another collection than the one confirmed.", good,
        err("approval_fields"), exp=dict(expect, fields=dict(fields, collection="c_0000")), attack="field-mismatch")
    add("field-extra", "The stored action has a field the confirmation lacks.", good, err("approval_fields"),
        exp=dict(expect, fields=dict(fields, purge=True)), attack="field-mismatch")
    add("field-missing", "The confirmation has a field the stored action lacks.", good, err("approval_fields"),
        exp=dict(expect, fields={"collection": "c_81f2"}), attack="field-mismatch")
    add("field-type-int-string", "Confirmed the integer -1, stored the string \"-1\".", mixed, err("approval_fields"),
        exp={"type": QUOTA, "fields": dict(mixed_fields, quota="-1"), "sub": str(p.anna)}, attack="field-mismatch")
    add("field-type-bool-int", "Confirmed `false`, stored the integer 0.", mixed, err("approval_fields"),
        exp={"type": QUOTA, "fields": dict(mixed_fields, notify=0), "sub": str(p.anna)}, attack="field-mismatch")
    add("subject-other", "Confirmed by anna, the application acts for another account.", good, err("subject"),
        exp=dict(expect, sub=str(p.anna + 1000)), attack="subject")
    add("nonce-other", "The `nonce` is not the state in this session (a confirmation from another browser).",
        with_nonce, err("nonce"), exp=dict(expect, nonce="another-state"), attack="nonce")
    add("nonce-missing", "The application expects a state, the confirmation carries none.", good, err("nonce"),
        exp=dict(expect, nonce="k3J-browser.entry_7~"), attack="nonce")
    add("replay", "The `jti` is already in the application's store: the confirmation was used once.", good,
        err("replay"), seen=[base["jti"]], attack="replay")
    return out


# ---------- the file ----------

def build() -> dict:
    p = Probe()
    keys = {"_test_material": "TEST KEYS ONLY. The private seeds are derived from a public label and printed here so "
                              "that client authors can mint further test confirmations. Never use them anywhere else.",
            "keys": {label: {"role": role, "seed_label": seed_label, "d": gv.b64u(seed), "public_jwk": jwk(label)}
                     for label, role, seed_label, seed in (
                         ("P", "active approval key of the probe installation",
                          "tinysesam approval test vector key P", _seed("P")),
                         ("Q", "previous approval key after a rotation", "tinysesam approval test vector key Q",
                          _seed("Q")),
                         ("A", "the GATE key of spec/vectors/keys.json — never in an approval key set",
                          "tinysesam gate-client test vector key A", gv._seed("A")),
                         ("X", "the attacker's key, in no key set", "tinysesam approval test vector key X",
                          _seed("X")))}}
    try:
        doc = {"format": FORMAT, "kind": "approval", "spec": "spec/approval-token.md",
               "generated_by": "scripts/_approval_vectors.py — do not edit by hand",
               "defaults": {"issuer": ISSUER, "app_id": APP_ID, "now": NOW, "max_lifetime": 300, "max_leeway": 30},
               **keys, "vectors": vectors(p)}
        return {"approval.json": json.dumps(doc, indent=2, ensure_ascii=False) + "\n"}
    finally:
        p.close()


def main(argv) -> int:
    files = build()
    text = files["approval.json"]
    if "--check" in argv:
        if not os.path.exists(OUT) or gv._read(OUT) != text:
            print("stale approval vectors — run python scripts/_approval_vectors.py", file=sys.stderr)
            return 1
        print("approval vectors current")
        return 0
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("wrote spec/vectors/approval.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
