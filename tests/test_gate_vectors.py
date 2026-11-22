"""T-28: the language-neutral gate client vectors (`spec/vectors/`) against the code and a reference client.

`spec/gate-client.md` is the contract for gate clients in other languages (Go, Rust, JS/TS, PHP). Its vectors are
generated from TinySesam's own issuing path by `scripts/_gate_vectors.py`. This suite holds both ends together:

1. **Current:** the files are byte for byte what the generator produces from today's code — a change to the token,
   the claims or the `Remote-*` headers that does not reach the vectors turns red here.
2. **Complete:** every vector has an id, a reason and an attack class from the list below; every class of that list
   occurs. A class removed from the vectors is a hole a client would never be tested for.
3. **Passed:** the reference client (`tests/_gate_reference.py`, the executable reading of the specification) reaches
   every expected verdict, error class and identity.
4. **The server agrees:** `tinysesam.gate.check` (the proxy-side check) accepts every valid vector and rejects every
   vector whose class it checks too (signature, issuer, audience, time). Where it accepts an attack, the class must be
   one the client is deliberately stricter about.
5. **Self-probes:** every relaxation of the reference (`alg` taken from the header, an embedded `jwk` trusted,
   duplicates allowed, …) must fail at least one vector. A rule no vector can catch is not tested.
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
# The sdist ships tests/ but not spec/: there the suite declines. In the repo a missing directory is a failure.
braucht(os.path.isdir(VECTORS) or (pathlib.Path(ROOT) / ".git").exists(),
        "no spec/vectors (unpacked sdist) — the vectors live in the repository")
assert os.path.isdir(VECTORS), "spec/vectors is missing"

import _gate_reference as ref  # noqa: E402
from tinysesam import gate  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


def load(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        return json.load(f)


FILES = ("keys.json", "token.json", "headers.json", "jwks.json", "topbar.json")
TOKEN, HEADERS, JWKS, TOPBAR = (load(n) for n in FILES[1:])

#: The attack classes the vectors must cover (spec/gate-client.md, "Attack classes"). Keep both lists equal.
ATTACK_CLASSES = {
    "alg-none", "alg-confusion-hs256", "alg-wrong", "typ-wrong", "crit", "embedded-key", "header-unknown-member",
    "foreign-key", "kid-unknown", "kid-manipulated", "empty-signature", "bad-signature", "base64-padding",
    "base64-alphabet", "base64-noncanonical", "segments", "oversize", "jws-json-serialization", "duplicate-members",
    "json-encoding", "claim-types", "unicode-control", "unicode-homoglyph", "expired", "not-yet-valid", "lifetime",
    "issuer", "audience",
    "remote-auth", "groups-parsing", "header-missing-user", "header-duplicate", "header-injection", "header-encoding",
    "id-format",
    "jwks-entry", "jwks-shape", "jwks-cache",
    "topbar-href", "topbar-types",
}

# ---------- 1. current ----------
spec_gen = importlib.util.spec_from_file_location("_gate_vectors", os.path.join(ROOT, "scripts", "_gate_vectors.py"))
generator = importlib.util.module_from_spec(spec_gen)
spec_gen.loader.exec_module(generator)
fresh = generator.build()
assert sorted(fresh) == sorted(FILES), sorted(fresh)
stale = [n for n in FILES if generator._read(os.path.join(VECTORS, n)) != fresh[n]]
assert not stale, f"stale vectors {stale} — run: python scripts/_gate_vectors.py"
assert generator.build() == fresh, "the generator is not deterministic"
ok(f"spec/vectors: {len(FILES)} files current to the generator, two builds identical")

# The generator restores what it patched: gate.issue draws a random jti again afterwards.
_k = generator._private("A")
_t1 = gate.issue(_k, iss="i", aud="a", sub="1", claims={}, ttl=60, now=1)
_t2 = gate.issue(_k, iss="i", aud="a", sub="1", claims={}, ttl=60, now=1)
assert _t1 != _t2, "the generator left the fixed jti in place"
ok("the generator leaves gate.secrets and the clock as they were")

# ---------- 2. complete ----------
all_vectors = ([("token", v) for v in TOKEN["vectors"]] + [("headers", v) for v in HEADERS["vectors"]]
               + [("jwks", v) for v in JWKS["sets"]] + [("jwks", v) for v in JWKS["scenarios"]]
               + [("topbar", v) for v in TOPBAR["vectors"]])
ids = [f"{kind}/{v['id']}" for kind, v in all_vectors]
assert len(ids) == len(set(ids)), "duplicate vector ids"
for kind, v in all_vectors:
    assert isinstance(v.get("reason"), str) and len(v["reason"]) >= 12, f"{kind}/{v['id']}: no reason"
    assert v.get("attack") is None or v["attack"] in ATTACK_CLASSES, f"{kind}/{v['id']}: unknown class {v['attack']}"
covered = {v["attack"] for _k, v in all_vectors if v.get("attack")}
missing = ATTACK_CLASSES - covered
assert not missing, f"attack classes without a vector: {sorted(missing)}"
for v in TOKEN["vectors"]:
    e = v["expected"]
    assert e["ok"] or e["error"] in ref.ERRORS, (v["id"], e)
    assert v["id"].startswith("valid-") == e["ok"], f"{v['id']}: the name says the opposite of the verdict"
spec_text = generator._read(os.path.join(ROOT, "spec", "gate-client.md"))
undocumented = sorted(c for c in ATTACK_CLASSES if f"`{c}`" not in spec_text)
assert not undocumented, f"attack classes missing from spec/gate-client.md: {undocumented}"
unknown_errors = sorted(c for c in ref.ERRORS + ref.HEADER_ERRORS + ("jwks_invalid",) if f"`{c}`" not in spec_text)
assert not unknown_errors, f"error classes missing from spec/gate-client.md: {unknown_errors}"
ok(f"{len(all_vectors)} vectors, each with id and reason; all {len(ATTACK_CLASSES)} attack classes covered and "
   "named in the spec")


# ---------- 3. the reference client passes ----------

def keys_of(doc):
    return ref.parse_jwks(doc)


def run_token(v, relax=frozenset()):
    i = v["input"]
    try:
        claims = ref.verify(i["jws"], keys=keys_of(i["jwks"]), issuer=i["issuer"], audience=i["audience"],
                            now=i["now"], leeway=i["leeway"], relax=relax)
    except ref.GateError as e:
        return {"ok": False, "error": e.kind}
    out = {"ok": True, "claims": claims, "identity": ref.identity_from_claims(claims, relax)}
    if "has_role" in v["expected"]:
        out["has_role"] = {r: ref.has_role(out["identity"], r) for r in v["expected"]["has_role"]}
    return out


def run_headers(v, relax=frozenset()):
    try:
        ident = ref.identity_from_headers(v["input"]["headers"], relax)
    except ref.GateError as e:
        return {"ok": False, "error": e.kind}
    out = {"ok": True, "identity": ident}
    if "has_role" in v["expected"]:
        out["has_role"] = {r: ref.has_role(ident, r) for r in v["expected"]["has_role"]}
    return out


def run_set(v, relax=frozenset()):
    try:
        return {"ok": True, "kids": list(ref.parse_jwks(v["input"]["jwks"], relax))}
    except ref.GateError as e:
        return {"ok": False, "error": e.kind}


def run_scenario(v, relax=frozenset()):
    """The verdict of every step, or the first step whose fetch behaviour differs."""
    d = TOKEN["defaults"]
    state = {}

    def fetch(now):
        state["fetched"] = True
        if "fetch" not in state["step"]:
            raise _UnexpectedFetch(now)
        return state["step"]["fetch"]

    cache = ref.JwksCache(fetch, relax)
    results = []
    for step in v["steps"]:
        state.update(step=step, fetched=False)
        try:
            cache.verify(step["jws"], issuer=d["issuer"], audience=d["audience"], now=step["now"])
            got = {"fetched": state["fetched"], "ok": True}
        except ref.GateError as e:
            got = {"fetched": state["fetched"], "ok": False, "error": e.kind}
        except _UnexpectedFetch:
            got = {"fetched": True, "ok": None, "error": "unexpected fetch"}
        results.append(got)
    return results


class _UnexpectedFetch(Exception):
    pass


def run_topbar(v, relax=frozenset()):
    return {"ok": True, "topbar": ref.topbar(v["input"]["topbar"], relax)}


def mismatches(relax=frozenset()) -> list:
    bad = []
    for v in TOKEN["vectors"]:
        if run_token(v, relax) != v["expected"]:
            bad.append("token/" + v["id"])
    for v in HEADERS["vectors"]:
        if run_headers(v, relax) != v["expected"]:
            bad.append("headers/" + v["id"])
    for v in JWKS["sets"]:
        if run_set(v, relax) != v["expected"]:
            bad.append("jwks/" + v["id"])
    for v in JWKS["scenarios"]:
        if run_scenario(v, relax) != [s["expect"] for s in v["steps"]]:
            bad.append("jwks/" + v["id"])
    for v in TOPBAR["vectors"]:
        if run_topbar(v, relax) != v["expected"]:
            bad.append("topbar/" + v["id"])
    return bad


failed = mismatches()
if failed:
    for name in failed[:10]:
        print(f"  ✗ {name}")
    detail = []
    for v in TOKEN["vectors"]:
        if "token/" + v["id"] in failed:
            detail.append((v["id"], run_token(v), v["expected"].get("error")))
    raise AssertionError(f"the reference client misses {len(failed)} vectors: {failed[:10]} {detail[:5]}")
ok(f"reference client: {len(TOKEN['vectors'])} token, {len(HEADERS['vectors'])} header, "
   f"{len(JWKS['sets'])} key-set, {len(JWKS['scenarios'])} cache, {len(TOPBAR['vectors'])} top-bar vectors passed")

for bad in (-1, 61, True, 1.5, "0"):
    try:
        ref.check_leeway(bad)
    except ValueError:
        continue
    raise AssertionError(f"a clock leeway of {bad!r} was accepted")
assert ref.check_leeway(0) == 0 and ref.check_leeway(60) == 60
ok("clock leeway: 0–60 s accepted, anything else is a configuration error")

# ---------- 4. the server's check agrees where it checks the same ----------
STRICTER = {"malformed", "header", "kid", "claims", "lifetime"}   # what only the client refuses
SHARED = {"signature", "issuer", "audience", "not_yet_valid", "expired"}
agree = 0
for v in TOKEN["vectors"]:
    i, e = v["input"], v["expected"]
    if i["leeway"]:
        continue
    keys = keys_of(i["jwks"])
    try:
        head = json.loads(ref.b64u_decode(i["jws"].split(".")[0], frozenset({"lenient_base64"})))
        public = keys.get(head.get("kid")) if isinstance(head, dict) and isinstance(head.get("kid"), str) else None
    except (ValueError, ref.GateError, IndexError):
        public = None
    public = public or next(iter(keys.values()))
    got = gate.check(public, i["jws"], aud=i["audience"], iss=i["issuer"], now=i["now"])
    if e["ok"]:
        assert got == e["claims"], f"gate.check refuses the valid vector {v['id']}"
    elif e["error"] in SHARED:
        assert got is None, f"gate.check accepts {v['id']} ({e['error']})"
    else:
        assert got is None or e["error"] in STRICTER, (v["id"], e["error"])
    agree += 1
ok(f"gate.check: same verdict on {agree} vectors where it checks the same; stricter client classes {sorted(STRICTER)}")

# The header vectors of the session come from the server's own headers — the reference reads back what it sends.
probe = generator.Probe()
try:
    for name in ("anna", "juergen", "ivan"):
        sent = probe.headers(name)
        got = ref.identity_from_headers(sent)
        u = probe.auth.get_user(probe.users[name])
        assert got["user"] == u["username"] and got["id"] == str(u["id"]) and got["kind"] == "session", got
        assert got["groups"] == probe.auth.user_roles(u), (got, probe.auth.user_roles(u))
finally:
    probe.close()
ok("header mode: the reference reads back what _forward_response_headers sends (UTF-8, groups, id, kind)")

# ---------- 5. self-probes: every rule is measured by at least one vector ----------
silent = []
for relax in ref.RELAXATIONS:
    caught = mismatches(frozenset({relax}))
    if not caught:
        silent.append(relax)
assert not silent, f"relaxations no vector catches: {silent}"
ok(f"self-probes: each of the {len(ref.RELAXATIONS)} relaxations of the reference fails at least one vector")

# ---------- 6. one defect per attack vector ----------
# A vector with two defects of the same class passes a client that lacks the check it is named for: until 2026-11-22
# `attack-payload-invalid-utf8` also repeated `ts_name`, so a client without a UTF-8 check still answered `malformed`
# through its duplicate check. Rule: switching off exactly one check of the reference (one relaxation, or the key that
# is missing from the set) turns every attack vector into an accepted one. Where no single repair exists because the
# defect cannot occur alone, the vector is listed below with the reason; the list is measured both ways.
TEST_KEYS = {label: k["public_jwk"] for label, k in load("keys.json")["keys"].items()}
INHERENT = {
    # A kid of the wrong form can never be in a key set (§4.3 ties a kid to its key): format check and lookup fail
    # together. The cache scenario `invalid-kid-no-fetch` measures the format check on its own.
    **{f"token/attack-kid-{s}": "kid" for s in ("missing", "path", "sql", "long", "number", "uppercase", "nul")},
    # No single repair restores a token that is not three segments, or a header/payload that is no object.
    **{f"token/attack-{s}": "structure" for s in ("two-segments", "four-segments", "trailing-dot",
                                                   "five-segments-jwe", "empty-header", "jws-json-flattened",
                                                   "jws-json-general", "header-array", "payload-array")},
    # A missing claim has no value a repair could assume; a boolean or a huge exp turns into a wrong lifetime.
    **{f"token/attack-claim-{s}": "claim" for s in ("nbf-missing", "iat-missing", "sub-missing", "iss-missing",
                                                    "exp-bool", "exp-huge", "sub-number", "aud-number",
                                                    "aud-empty-array")},
    # exp before nbf: no instant at which the token is valid, the lifetime repaired leaves it expired.
    "token/attack-lifetime-negative": "time",
    # Without Remote-User there is nobody to repair.
    "headers/user-missing": "nobody", "headers/user-empty": "nobody",
}


def repairs(kind, v) -> list:
    """The single repairs under which an attack vector is accepted."""
    found = []
    if kind == "token":
        for relax in ref.RELAXATIONS:
            if run_token(v, frozenset({relax}))["ok"]:
                found.append(relax)
        widened = dict(v, input=dict(v["input"], jwks={"keys": list(TEST_KEYS.values())}))
        if run_token(widened)["ok"]:
            found.append("key in the set")
        try:   # a repair of the configuration: issuer and audience as the token names them
            c = json.loads(ref.b64u_decode(v["input"]["jws"].split(".")[1]))
            aud = c["aud"] if isinstance(c["aud"], str) else c["aud"][-1]
            for field, value in (("issuer", c["iss"]), ("audience", aud)):
                if run_token(dict(v, input=dict(v["input"], **{field: value})))["ok"]:
                    found.append(f"configured {field}")
        except (ValueError, KeyError, IndexError, TypeError, ref.GateError):
            pass
    else:
        found = [r for r in ref.RELAXATIONS if run_headers(v, frozenset({r}))["ok"]]
    return found


def unrepairable(vectors) -> list:
    return [f"{kind}/{v['id']}" for kind, v in vectors if not repairs(kind, v)]


attack_vectors = ([("token", v) for v in TOKEN["vectors"] if not v["expected"]["ok"]]
                  + [("headers", v) for v in HEADERS["vectors"] if not v["expected"]["ok"]])
lonely = unrepairable(attack_vectors)
assert sorted(set(lonely) - set(INHERENT)) == [], f"attack vectors with more than one defect: {sorted(set(lonely) - set(INHERENT))}"
assert sorted(set(INHERENT) - set(lonely)) == [], f"listed as inherent but repairable: {sorted(set(INHERENT) - set(lonely))}"
# Self-probe: the old double defect (invalid UTF-8 plus a repeated claim) is found.
_double = json.loads(json.dumps(next(v for v in TOKEN["vectors"] if v["id"] == "attack-payload-invalid-utf8")))
_body = generator.enc(generator.claims_of(next(v for v in TOKEN["vectors"] if v["id"] == "valid-session")["input"]["jws"]))
_double["input"]["jws"] = generator.signed(generator.head(), _body[:-1] + b',"ts_name":"\xff"}')
assert unrepairable([("token", _double)]) == ["token/attack-payload-invalid-utf8"], "the one-defect guard is blind"
_jwk_a = TEST_KEYS["A"]
for v in JWKS["sets"]:
    if v["attack"] == "jwks-entry" and v["id"] != "duplicate-kid":
        e = v["input"]["jwks"]["keys"][0]
        changed = {m for m in set(e) | set(_jwk_a) if e.get(m, None) != _jwk_a.get(m, None)}
        try:   # a kid recomputed for a changed x follows the x: one defect, not two
            if {"x", "kid"} <= changed and e["kid"] == ref.key_id(ref.b64u_decode(e["x"])):
                changed.discard("kid")
        except (ref.GateError, KeyError, TypeError):
            pass
        assert len(changed) == 1, f"jwks/{v['id']}: the skipped entry differs from a usable one in {sorted(changed)}"
ok(f"one defect: {len(attack_vectors) - len(INHERENT)} attack vectors accepted after one repair, {len(INHERENT)} "
   "listed where the defect cannot occur alone; key-set entries differ from a usable one in one member")

# The keys file says what it is: test material, and the public halves match the seeds.
keys_doc = load("keys.json")
assert "TEST KEYS ONLY" in keys_doc["_test_material"]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
for label, k in keys_doc["keys"].items():
    seed = base64.urlsafe_b64decode(k["d"] + "=" * (-len(k["d"]) % 4))
    assert seed == generator._seed(label)
    assert ref.b64u_encode(gate.public_raw(Ed25519PrivateKey.from_private_bytes(seed))) == k["public_jwk"]["x"]
    assert ref.jwk_entry(k["public_jwk"]) is not None, label
ok("keys.json: marked as test material, every public key matches its seed and is a usable JWK")
