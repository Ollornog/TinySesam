"""T-89 stage B: the language-neutral approval confirmation vectors (`spec/vectors/approval.json`) against the code
and the Python reference `tinysesam.approval_token.verify`.

`spec/approval-token.md` is the contract for the approval helpers of every client. Its vectors are generated from
TinySesam's own issuing path by `scripts/_approval_vectors.py`. This suite holds both ends together:

1. **Current:** the file is byte for byte what the generator produces from today's code, and two builds agree.
2. **Complete:** every vector has an id, a reason and an attack class of the list below; every class occurs, and the
   spec names every class and every error class.
3. **Passed:** the reference reaches every expected verdict and error class (and the claims of the valid ones).
4. **Self-probes:** every relaxation of the reference (`tests/_approval_relax.py`: `typ` not checked, the gate keys
   trusted, `aud` as an array, a second entry, the digest skipped, …) fails at least one vector.
5. **One defect:** every attack vector is accepted after exactly one relaxation, or is listed with the reason why its
   defect cannot occur alone.
6. **Server and gate agree:** a confirmation is no gate token — `gate.check` and the gate client refuse it — and the
   real gate token in the vectors is refused by the reference.
"""
import base64
import importlib.util
import json
import os
import pathlib
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

from voraussetzung import braucht  # noqa: E402

VECTORS = os.path.join(ROOT, "spec", "vectors")
braucht(os.path.isdir(VECTORS) or (pathlib.Path(ROOT) / ".git").exists(),
        "no spec/vectors (unpacked sdist) — the vectors live in the repository")

import _approval_relax as relax_mod  # noqa: E402
from tinysesam import approval_token as at  # noqa: E402
from tinysesam import gate  # noqa: E402
from tinysesam import gate_client as gc  # noqa: E402

ERRORS = ("malformed", "header", "kid", "signature", "claims", "issuer", "audience", "lifetime", "not_yet_valid",
          "expired", "key_unavailable", "approval_type", "approval_fields", "subject", "nonce", "replay")
#: The attack classes the vectors must cover (spec/approval-token.md, "Attack classes"). Keep both lists equal.
ATTACK_CLASSES = {"typ-wrong", "alg-wrong", "embedded-key", "gate-token", "gate-key", "foreign-key", "bad-signature",
                  "aud-array", "details-count", "hash-mismatch", "claim-types", "unicode-control", "issuer",
                  "audience", "lifetime", "expired", "not-yet-valid", "type-mismatch", "field-mismatch", "subject",
                  "nonce", "replay"}
#: Attack vectors whose defect cannot be repaired by switching off one rule — with the reason.
NOT_ONE_DEFECT = {
    "gate-token": "a real gate token differs in everything: typ, key, claims (ts_*, no authorization_details)",
    "foreign-key-trusted-kid": "a signature by another key under a trusted kid has no repair short of the private key",
    "kid-retired": "the defect is the key set of the vector (Q retired), not the token",
    "payload-changed": "a changed payload under the old signature has no repair short of the private key",
    "details-empty": "an empty array has no entry a lenient check could accept",
    "auth-time-missing": "a missing claim cannot be repaired by a lenient check of the others",
    "act-missing": "a missing claim cannot be repaired by a lenient check of the others",
    "jti-missing": "a missing claim cannot be repaired by a lenient check of the others",
    "field-object": "an object value is refused as a type and differs from the stored string as a field",
}


def ok(name):
    print(f"  ✓ {name}")


with open(os.path.join(VECTORS, "approval.json"), encoding="utf-8") as f:
    DOC = json.load(f)
VECS = DOC["vectors"]

# ---------- 1. current ----------
spec_gen = importlib.util.spec_from_file_location("_approval_vectors", os.path.join(ROOT, "scripts",
                                                                                    "_approval_vectors.py"))
generator = importlib.util.module_from_spec(spec_gen)
spec_gen.loader.exec_module(generator)
fresh = generator.build()
with open(os.path.join(VECTORS, "approval.json"), encoding="utf-8") as f:
    assert f.read() == fresh["approval.json"], "stale vectors — run: python scripts/_approval_vectors.py"
assert generator.build() == fresh, "the generator is not deterministic"
assert DOC["format"] == generator.FORMAT == 1 and DOC["spec"] == "spec/approval-token.md"
spec_text = pathlib.Path(ROOT, "spec", "approval-token.md").read_text(encoding="utf-8")
assert "Version 1 (format 1 of `vectors/approval.json`)" in spec_text
ok(f"spec/vectors/approval.json: {len(VECS)} vectors current to the generator, two builds identical, format 1")

# The generator restores what it patched: the clock of the approvals and the probe's keyring.
from tinysesam import approvals as _apv  # noqa: E402
assert abs(_apv._now() - __import__("time").time()) < 5, "the generator left the fixed clock in place"
ok("the generator leaves the approvals' clock as it was")

# ---------- 2. complete ----------
ids = [v["id"] for v in VECS]
assert len(ids) == len(set(ids)), "duplicate vector ids"
for v in VECS:
    assert isinstance(v.get("reason"), str) and len(v["reason"]) >= 12, f"{v['id']}: no reason"
    assert v["attack"] is None or v["attack"] in ATTACK_CLASSES, f"{v['id']}: unknown class {v['attack']}"
    e = v["expected"]
    assert e["ok"] or e["error"] in ERRORS, (v["id"], e)
    assert v["id"].startswith("valid-") == e["ok"] == (v["attack"] is None), f"{v['id']}: name, verdict, class"
missing = ATTACK_CLASSES - {v["attack"] for v in VECS if v["attack"]}
assert not missing, f"attack classes without a vector: {sorted(missing)}"
undocumented = sorted(c for c in ATTACK_CLASSES | set(ERRORS) if f"`{c}`" not in spec_text)
assert not undocumented, f"classes missing from spec/approval-token.md: {undocumented}"
assert set(NOT_ONE_DEFECT) <= set(ids), set(NOT_ONE_DEFECT) - set(ids)
# Every vector's key set is the APPROVAL set: never the gate key A.
gate_kid = generator.kid("A")
assert all(gate_kid not in [k["kid"] for k in v["input"]["jwks"]["keys"]] for v in VECS), "gate key in a key set"
ok(f"{len(VECS)} vectors, each with id and reason; all {len(ATTACK_CLASSES)} attack classes covered and documented; "
   f"no key set holds the gate key")


# ---------- 3. passed ----------
def run(v):
    """(True, claims) or (False, error class) of the reference for one vector."""
    i = v["input"]
    seen = set(i["seen"])

    def store(jti, until):
        if jti in seen:
            return False
        seen.add(jti)
        return True
    e = i["expect"]
    try:
        claims = at.verify(i["jws"], keys=i["jwks"], issuer=i["issuer"], app_id=i["app_id"], expect_type=e["type"],
                           expect_fields=e["fields"], expect_sub=e["sub"], expect_nonce=e.get("nonce"),
                           jti_store=store, now=i["now"], leeway=i["leeway"])
    except gc.GateError as err:
        return False, err.kind
    return True, claims


def verdict_matches(v) -> bool:
    good, got = run(v)
    e = v["expected"]
    return (good and e["ok"] and got == e["claims"]) or (not good and not e["ok"] and got == e["error"])


wrong = [(v["id"], run(v)) for v in VECS if not verdict_matches(v)]
assert not wrong, wrong[:5]
ok(f"the reference reaches every verdict: {sum(v['expected']['ok'] for v in VECS)} valid with their claims, "
   f"{sum(not v['expected']['ok'] for v in VECS)} refused with the expected class")

# A replay needs no vector state: the same confirmation twice against ONE store passes once.
valid = next(v for v in VECS if v["id"] == "valid-basic")
memory: set = set()


def once(jti, until):
    if jti in memory:
        return False
    memory.add(jti)
    return True


kw = dict(keys=valid["input"]["jwks"], issuer=generator.ISSUER, app_id="example",
          expect_type=valid["input"]["expect"]["type"], expect_fields=valid["input"]["expect"]["fields"],
          expect_sub=valid["input"]["expect"]["sub"], jti_store=once, now=valid["input"]["now"])
at.verify(valid["input"]["jws"], **kw)
try:
    at.verify(valid["input"]["jws"], **kw)
    raise AssertionError("the second use passed")
except at.ReplayError:
    pass
ok("one store: the first use passes, the second is `replay`")

# ---------- 4. self-probes ----------
for name in relax_mod.RELAXATIONS:
    with relax_mod.relaxed(name):
        caught = [v["id"] for v in VECS if not verdict_matches(v)]
    assert caught, f"relaxation {name!r}: no vector notices it — the rule is not measured"
ok(f"every one of {len(relax_mod.RELAXATIONS)} relaxations fails at least one vector")
assert all(verdict_matches(v) for v in VECS), "a relaxation was left in place"

# ---------- 5. one defect ----------
for v in VECS:
    if v["expected"]["ok"]:
        continue
    repaired = []
    for name in relax_mod.RELAXATIONS:
        with relax_mod.relaxed(name):
            if run(v)[0]:
                repaired.append(name)
    if v["id"] in NOT_ONE_DEFECT:
        assert not repaired, f"{v['id']} is listed as not repairable, but {repaired} accept it"
    else:
        assert repaired, f"{v['id']}: no single relaxation accepts it — more than one defect"
ok(f"every attack vector is accepted after one relaxation, {len(NOT_ONE_DEFECT)} listed with their reason")

# ---------- 6. server and gate ----------
gate_token = next(v for v in VECS if v["id"] == "gate-token")["input"]["jws"]
confirmation = valid["input"]["jws"]
public_a = base64.urlsafe_b64decode(DOC["keys"]["A"]["public_jwk"]["x"] + "==")
public_p = base64.urlsafe_b64decode(DOC["keys"]["P"]["public_jwk"]["x"] + "==")
# The proxy-side check and the gate client, even holding the approval key: a confirmation is no gate token (typ).
assert gate.check(public_a, confirmation, aud="example", iss=generator.ISSUER, now=generator.NOW) is None
assert gate.check(public_p, confirmation, aud="example", iss=generator.ISSUER, now=generator.NOW) is None, \
    "gate.check took a confirmation for a gate token (typ)"
try:
    gc._verify(confirmation, lambda kid: public_p, issuer=generator.ISSUER, audience="example", now=generator.NOW,
               leeway=0)
    raise AssertionError("the gate client took a confirmation for a gate token")
except gc.HeaderError:
    pass
ok("a confirmation is no gate token: gate.check and the gate client refuse it (typ), whatever key they hold")

print("OK test_approval_vectors")
