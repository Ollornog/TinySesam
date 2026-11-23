"""T-28/T-86: the language-neutral gate client vectors (`spec/vectors/`) against the code and the Python gate client.

`spec/gate-client.md` is the contract for gate clients in other languages (Go, Rust, JS/TS, PHP). Its vectors are
generated from TinySesam's own issuing path by `scripts/_gate_vectors.py`. This suite holds both ends together:

1. **Current:** the files are byte for byte what the generator produces from today's code — a change to the token,
   the claims or the `Remote-*` headers that does not reach the vectors turns red here.
2. **Complete:** every vector has an id, a reason and an attack class from the list below; every class of that list
   occurs. A class removed from the vectors is a hole a client would never be tested for.
3. **Passed:** the Python gate client `tinysesam.gate_client` reaches every expected verdict, error class and
   identity, through its public `GateClient` (token mode with fixed keys, header mode) and its key set cache.
4. **The server agrees:** `tinysesam.gate.check` (the proxy-side check) accepts every valid vector and rejects every
   vector whose class it checks too (signature, issuer, audience, time). Where it accepts an attack, the class must be
   one the client is deliberately stricter about.
5. **Self-probes:** every relaxation of the client (`tests/_gate_relax.py`: `alg` taken from the header, an embedded
   `jwk` trusted, duplicates allowed, …) must fail at least one vector. A rule no vector can catch is not tested.
6. **One defect:** every attack vector is accepted after exactly one repair (one relaxation, the missing key, the
   issuer or audience it names), or is listed with the reason why its defect cannot occur alone.
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

import dataclasses  # noqa: E402

import _gate_relax as relax_mod  # noqa: E402
from tinysesam import gate  # noqa: E402
from tinysesam import gate_client as gc  # noqa: E402
from tinysesam.errors import ConfigError  # noqa: E402

ERRORS = ("malformed", "header", "kid", "signature", "claims", "issuer", "audience", "lifetime", "not_yet_valid",
          "expired", "key_unavailable")
HEADER_ERRORS = ("unauthenticated", "header")
RELAXATIONS = tuple(relax_mod.RELAXATIONS)


def ok(name):
    print(f"  ✓ {name}")


def load(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        return json.load(f)


FILES = ("keys.json", "token.json", "headers.json", "jwks.json", "topbar.json", "account.json")
TOKEN, HEADERS, JWKS, TOPBAR, ACCOUNT = (load(n) for n in FILES[1:])

#: The attack classes the vectors must cover (spec/gate-client.md, "Attack classes"). Keep both lists equal.
ATTACK_CLASSES = {
    "alg-none", "alg-confusion-hs256", "alg-wrong", "typ-wrong", "crit", "embedded-key", "header-unknown-member",
    "foreign-key", "kid-unknown", "kid-manipulated", "empty-signature", "bad-signature", "base64-padding",
    "base64-alphabet", "base64-noncanonical", "segments", "oversize", "jws-json-serialization", "duplicate-members",
    "json-encoding", "claim-types", "unicode-control", "unicode-homoglyph", "expired", "not-yet-valid", "lifetime",
    "issuer", "audience",
    "remote-auth", "remote-kind", "groups-parsing", "header-missing-user", "header-duplicate", "header-injection", "header-encoding",
    "id-format",
    "jwks-entry", "jwks-shape", "jwks-cache",
    "topbar-href", "topbar-types", "account-href", "account-types",
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
# Spec version 2: a client checks the format of its vectors, so that a newer file cannot pass an older client unseen.
assert generator.FORMAT == 2 and all(load(n)["format"] == 2 for n in FILES), [load(n)["format"] for n in FILES]
assert "Version 2 (format 2 of the vectors)" in generator._read(os.path.join(ROOT, "spec", "gate-client.md"))
ok(f"spec/vectors: {len(FILES)} files current to the generator, two builds identical, format 2 = spec version 2")

# The generator restores what it patched: gate.issue draws a random jti again afterwards.
_k = generator._private("A")
_t1 = gate.issue(_k, iss="i", aud="a", sub="1", claims={}, ttl=60, now=1)
_t2 = gate.issue(_k, iss="i", aud="a", sub="1", claims={}, ttl=60, now=1)
assert _t1 != _t2, "the generator left the fixed jti in place"
ok("the generator leaves gate.secrets and the clock as they were")

# ---------- 2. complete ----------
all_vectors = ([("token", v) for v in TOKEN["vectors"]] + [("headers", v) for v in HEADERS["vectors"]]
               + [("jwks", v) for v in JWKS["sets"]] + [("jwks", v) for v in JWKS["scenarios"]]
               + [("topbar", v) for v in TOPBAR["vectors"]] + [("account", v) for v in ACCOUNT["vectors"]])
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
    assert e["ok"] or e["error"] in ERRORS, (v["id"], e)
    assert v["id"].startswith("valid-") == e["ok"], f"{v['id']}: the name says the opposite of the verdict"
spec_text = generator._read(os.path.join(ROOT, "spec", "gate-client.md"))
undocumented = sorted(c for c in ATTACK_CLASSES if f"`{c}`" not in spec_text)
assert not undocumented, f"attack classes missing from spec/gate-client.md: {undocumented}"
unknown_errors = sorted(c for c in ERRORS + HEADER_ERRORS + ("jwks_invalid",) if f"`{c}`" not in spec_text)
assert not unknown_errors, f"error classes missing from spec/gate-client.md: {unknown_errors}"
ok(f"{len(all_vectors)} vectors, each with id and reason; all {len(ATTACK_CLASSES)} attack classes covered and "
   "named in the spec")


# ---------- 3. the gate client passes ----------

def gate_keys(doc):
    """The fixed keys of a vector's key set, as `tinysesam gate-key` prints them."""
    return [base64.b64encode(public).decode("ascii") for public in gc._parse_jwks(doc).values()]


def identity_dict(identity):
    d = dataclasses.asdict(identity)
    d["groups"] = list(d["groups"])
    return d


def run_token(v, relax=frozenset()):
    i = v["input"]
    with relax_mod.relaxed(*relax):
        client = gc.GateClient(mode="token", issuer=i["issuer"], audience=i["audience"],
                               gate_keys=gate_keys(i["jwks"]), leeway=i["leeway"])
        try:
            identity, claims = client.verify(i["jws"], now=i["now"])
        except gc.GateError as e:
            return {"ok": False, "error": e.kind}
    out = {"ok": True, "claims": claims, "identity": identity_dict(identity)}
    if "has_role" in v["expected"]:
        out["has_role"] = {r: identity.has_role(r) for r in v["expected"]["has_role"]}
    return out


def run_headers(v, relax=frozenset()):
    with relax_mod.relaxed(*relax):
        try:
            identity = gc.GateClient(mode="header").identify(v["input"]["headers"])
        except gc.GateError as e:
            return {"ok": False, "error": e.kind}
    out = {"ok": True, "identity": identity_dict(identity)}
    if "has_role" in v["expected"]:
        out["has_role"] = {r: identity.has_role(r) for r in v["expected"]["has_role"]}
    return out


def run_set(v, relax=frozenset()):
    with relax_mod.relaxed(*relax):
        try:
            return {"ok": True, "kids": list(gc._parse_jwks(v["input"]["jwks"]))}
        except gc.GateError as e:
            return {"ok": False, "error": e.kind}


def fetch_result(answer):
    """A simulated fetch answer of the vectors, as the client's fetcher returns it."""
    if "error" in answer:
        return gc._FetchResult(error=answer["error"])
    body = (json.dumps(answer["body"]).encode("utf-8") if "body" in answer
            else str(answer.get("body_text", "")).encode("utf-8"))
    return gc._FetchResult(status=answer.get("status", 0), cache_control=answer.get("cache_control") or "", body=body)


def run_scenario(v, relax=frozenset()):
    """The verdict of every step; a fetch where the step gives no answer fails the step."""
    d = TOKEN["defaults"]
    state = {}

    def fetch():
        state["fetched"] = True
        if "fetch" not in state["step"]:
            state["unexpected"] = True
            return gc._FetchResult(error="unexpected")
        return fetch_result(state["step"]["fetch"])

    results = []
    with relax_mod.relaxed(*relax):
        client = gc.GateClient(mode="token", issuer=d["issuer"], audience=d["audience"],
                               jwks_url="https://auth.example.com/auth/gate/jwks.json")
        client._cache = gc._JWKSCache(fetch)
        for step in v["steps"]:
            state.update(step=step, fetched=False, unexpected=False)
            try:
                client.verify(step["jws"], now=step["now"])
                got = {"fetched": state["fetched"], "ok": True}
            except gc.GateError as e:
                got = {"fetched": state["fetched"], "ok": False, "error": e.kind}
            if state["unexpected"]:
                got = {"fetched": True, "ok": None, "error": "unexpected fetch"}
            results.append(got)
    return results


def run_topbar(v, relax=frozenset()):
    with relax_mod.relaxed(*relax):
        return {"ok": True, "topbar": gc.parse_topbar(v["input"]["topbar"]).to_dict()}


def run_account(v, relax=frozenset()):
    with relax_mod.relaxed(*relax):
        return {"ok": True, "account": gc.parse_account(v["input"]["account"])}


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
    for v in ACCOUNT["vectors"]:
        if run_account(v, relax) != v["expected"]:
            bad.append("account/" + v["id"])
    return bad


failed = mismatches()
if failed:
    for name in failed[:10]:
        print(f"  ✗ {name}")
    detail = []
    for v in TOKEN["vectors"]:
        if "token/" + v["id"] in failed:
            detail.append((v["id"], run_token(v), v["expected"].get("error")))
    raise AssertionError(f"the gate client misses {len(failed)} vectors: {failed[:10]} {detail[:5]}")
ok(f"gate client: {len(TOKEN['vectors'])} token, {len(HEADERS['vectors'])} header, "
   f"{len(JWKS['sets'])} key-set, {len(JWKS['scenarios'])} cache, {len(TOPBAR['vectors'])} top-bar, "
   f"{len(ACCOUNT['vectors'])} account vectors passed")

_token_cfg = {"mode": "token", "issuer": "https://auth.example.com", "audience": "app.example.com",
              "gate_keys": [load("keys.json")["keys"]["A"]["sign_key_base64"]]}
for bad in (-1, 61, True, 1.5, "0"):
    try:
        gc.GateClient(**_token_cfg, leeway=bad)
    except ConfigError:
        continue
    raise AssertionError(f"a clock leeway of {bad!r} was accepted")
assert gc.GateClient(**_token_cfg, leeway=0) and gc.GateClient(**_token_cfg, leeway=60)
ok("clock leeway: 0–60 s accepted, anything else is a configuration error")

# ---------- 4. the server's check agrees where it checks the same ----------
STRICTER = {"malformed", "header", "kid", "claims", "lifetime"}   # what only the client refuses
SHARED = {"signature", "issuer", "audience", "not_yet_valid", "expired"}
agree = 0
for v in TOKEN["vectors"]:
    i, e = v["input"], v["expected"]
    if i["leeway"]:
        continue
    keys = gc._parse_jwks(i["jwks"])
    try:
        head = json.loads(relax_mod._lenient_b64(i["jws"].split(".")[0]))
        public = keys.get(head.get("kid")) if isinstance(head, dict) and isinstance(head.get("kid"), str) else None
    except (ValueError, gc.GateError, IndexError):
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
        got = gc.GateClient(mode="header").identify(sent)
        u = probe.auth.get_user(probe.users[name])
        assert got.user == u["username"] and got.id == str(u["id"]) and got.is_session(), got
        assert list(got.groups) == probe.auth.user_roles(u), (got, probe.auth.user_roles(u))
        assert got.account_kind == "user" and not got.is_service(), got
    got = gc.GateClient(mode="header").identify(probe.headers("service", "apikey"))
    assert got.account_kind == "service" and got.is_service() and not got.is_session(), got
finally:
    probe.close()
ok("header mode: the client reads back what _forward_response_headers sends (UTF-8, groups, id, kind, account kind)")

# ---------- 5. self-probes: every rule is measured by at least one vector ----------
before = relax_mod.snapshot()
silent = []
for relax in RELAXATIONS:
    caught = mismatches(frozenset({relax}))
    if not caught:
        silent.append(relax)
assert not silent, f"relaxations no vector catches: {silent}"
assert relax_mod.snapshot() == before, "a relaxation was not restored"
# Every check function of the client has a relaxation: a check without one is a rule nobody measures.
patched = {a for spec in relax_mod.RELAXATIONS.values() for a in spec}
NOT_A_RULE = {"_check_claims", "_check_leeway", "_check_fetch_url",   # a sequence of checks, configuration checks
              "_check_size"}                                          # relaxed through _MAX_TOKEN_BYTES
checks = {n for n in vars(gc) if n.startswith("_check_") and callable(getattr(gc, n))}
assert checks - patched - NOT_A_RULE == set(), f"checks without a relaxation: {sorted(checks - patched - NOT_A_RULE)}"
assert NOT_A_RULE <= checks, sorted(NOT_A_RULE - checks)
ok(f"self-probes: each of the {len(RELAXATIONS)} relaxations of the client fails at least one vector; every check "
   f"function ({len(checks - NOT_A_RULE)}) has one; the module is restored afterwards")

# ---------- 6. one defect per attack vector ----------
# A vector with two defects of the same class passes a client that lacks the check it is named for: until 2026-11-22
# `attack-payload-invalid-utf8` also repeated `ts_name`, so a client without a UTF-8 check still answered `malformed`
# through its duplicate check. Rule: switching off exactly one check of the client (one relaxation, or the key that
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
                                                    "exp-bool", "exp-huge", "aud-number",
                                                    "aud-empty-array", "kind-type")},
    # exp before nbf: no instant at which the token is valid, the lifetime repaired leaves it expired.
    "token/attack-lifetime-negative": "time",
    # Without Remote-User there is nobody to repair.
    "headers/user-missing": "nobody", "headers/user-empty": "nobody", "headers/kind-missing-no-user": "nobody",
}


def readable_claims(jws) -> dict:
    """The payload of a token as a JSON object, or {} when it cannot be read (no configuration repair then)."""
    try:
        value = json.loads(gc._b64u_decode(jws.split(".")[1]))
    except (ValueError, IndexError, gc.GateError):
        return {}
    return value if isinstance(value, dict) else {}


def kid_follows_x(entry) -> bool:
    """True when an entry's kid is the kid rule over its own x — a kid recomputed for a changed x is not a second
    defect."""
    try:
        return entry["kid"] == gc._key_id(gc._b64u_decode(entry["x"]))
    except (gc.GateError, KeyError, TypeError):
        return False


def repairs(kind, v) -> list:
    """The single repairs under which an attack vector is accepted."""
    found = []
    if kind == "token":
        for relax in RELAXATIONS:
            if run_token(v, frozenset({relax}))["ok"]:
                found.append(relax)
        widened = dict(v, input=dict(v["input"], jwks={"keys": list(TEST_KEYS.values())}))
        if run_token(widened)["ok"]:
            found.append("key in the set")
        # A repair of the configuration: issuer and audience as the token names them (when it names them readably).
        c = readable_claims(v["input"]["jws"])
        aud = c.get("aud")
        targets = [("issuer", c.get("iss")), ("audience", aud if isinstance(aud, str) else
                                                          aud[-1] if isinstance(aud, list) and aud else None)]
        for field, value in targets:
            if isinstance(value, str) and run_token(dict(v, input=dict(v["input"], **{field: value})))["ok"]:
                found.append(f"configured {field}")
    else:
        found = [r for r in RELAXATIONS if run_headers(v, frozenset({r}))["ok"]]
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
        if {"x", "kid"} <= changed and kid_follows_x(e):
            changed.discard("kid")
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
    assert gc._b64u_encode(gate.public_raw(Ed25519PrivateKey.from_private_bytes(seed))) == k["public_jwk"]["x"]
    assert gc._jwk_entry(k["public_jwk"]) is not None, label
ok("keys.json: marked as test material, every public key matches its seed and is a usable JWK")
