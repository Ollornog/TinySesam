"""Pin down the public API — so a break gets NOTICED instead of just happening.

Milestone 1.0 demands that the public API does not break across two minor versions
(`backlog/M-1-api-stable-1-0.md`). Without measurement that is a claim: both most recent
releases broke it, and both times it was only noticed while writing the CHANGELOG.

This test pins the surface in `tests/api_surface.json` and compares on every run.
It records methods, class constants, since 0.20.1 also the properties (the cookie names),
the configuration fields with defaults, the presets and the exports, and since 0.22.0 also the
result types of the building blocks for custom pages (`LoginResult`, `PasswordChangeResult`:
fields, methods, reasons).
It forbids nothing — it forces a **deliberate decision**:

    python tests/test_api_surface.py --update      # accept the change, then commit

What counts as a break is defined below in `assess()`: removed or renamed is a break,
a changed signature usually is too, something new is an extension. The distinction
appears in the report, so nobody has to look up every line themselves.

**Since 0.22.0 every name carries a tier** (PO decision 2026-09-26, `TIERS` below): A is
permanently public and the only tier with the 1.0 commitment, B is for advanced users with a
weaker commitment, C is internal. Until then the surface was *measured, not chosen* —
what had no underscore was frozen. The tier is a decision, not a measurement:
it is stored per entry in `api_surface.json`, `--update` carries it over, but NEVER assigns
one itself. A new name comes in without a tier and keeps the guard red until someone enters one
— a silent "A" would have committed every helper method that happens to be created without an
underscore, for good.

**Tier C is only an alias since 0.22.0** (`tinysesam/_deprecated.py`): The implementation
is called `_name`, the old name keeps forwarding until 1.0 and warns. The guard additionally
pins down (`c_findings()`): every C entry is a `Deprecated` in the class and vice versa, it points to the
underscore implementation, calling it warns exactly once with the replacement and at the caller, no
code in the package uses an old name, and from 1.0 none is left.

**Tiers A and B are named in English** (PO decision 2026-09-27, `check_names()`): No name,
parameter, configuration field or attribute of an error type in tiers A/B carries a German
word — measured on the live object, with a minimum count and self-checks. **So do their keys
and values** (second PO decision of the same day, `check_values()`): what the surface returns
or accepts, the payload of `on_security_event`, the context of custom pages, the JSON of the routes
and the stored values — on a probe instance, on the constants and in the source, against the
word list and against every name up to 0.21.x (`OLD_VALUES`). It does not measure audit and log lines:
they stay as they are.
"""
import ast
import dataclasses
import inspect
import json
import os
import re
import subprocess
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import importlib
from tinysesam import ConfigError, LoginResult, PasswordChangeResult, TinySesam, TinySesamConfig, security
from tinysesam._deprecated import UNTIL, Deprecated

import _contract as CT           # static measurement: routes, header/cookie atoms, loggers, log lines, payloads
import _contract_probe as PR     # observed measurement: forward/gate responses, the hook, `auth.cfg`

_package = importlib.import_module("tinysesam")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STORAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_surface.json")

#: The tiers of the public surface (PO decision 2026-09-26). Only A carries the commitment
#: from M-1 ("two minor versions without a break"); the counter starts at 0.22.0.
TIERS = {
    "A": "public, stable from 1.0 — a break resets the 1.0 clock (M-1)",
    "B": "for advanced users — remove or rebuild only after a DeprecationWarning "
         "over two minor versions",
    "C": "internal — the implementation carries a leading underscore, the old name stays "
         "until 1.0 as an alias with DeprecationWarning (entry with `target`, `since`, `until`)",
}

#: Since when the C aliases warn (extra field `since` on every C entry).
C_SINCE = "0.22.0"

#: Under which key an entry in `api_surface.json` carries its MEASURED value.
#: Everything else on the entry (`tier`, later alias details) is a decision and is carried over by
#: `--update`, not re-measured. The exports have no measured value — only the name.
MEASURED_VALUE = {"TinySesam": "sig", "TinySesam.properties": "sig",
            "TinySesamConfig.methods": "sig", "TinySesam.constants": "value",
            "TinySesamConfig.fields": "field", "exports": None, "LoginResult": "sig",
            "PasswordChangeResult": "sig",
            # The operator and proxy contract (PO decision 2026-10-29, `tests/_contract.py`):
            "TinySesam.attributes": "value",         # `auth.cfg`, `auth.on_security_event`
            "TinySesam.event_payload": "keys",      # event -> keys of the `details` dict (list)
            "http.routes": "keys",                  # "METHOD /path" -> query/form parameters (list)
            "http.forward": "response",             # scenario -> status, contract headers, cookies
            "http.contract": None,                  # atoms: headers, reasons, request inputs, cookie names
            "log.loggers": None,                    # atoms: logger names
            "log.lines": None}                      # atoms: log-file format, line shapes, literal values

#: The result types of the building blocks for custom pages (0.22.0, tier A), each with its own area in
#: the baseline: `LoginResult` (`login_*`, `confirm_*`), `PasswordChangeResult` (`change_password`).
RESULT_TYPES = {"LoginResult": LoginResult, "PasswordChangeResult": PasswordChangeResult}


def ok(name):
    print(f"  ✓ {name}")


def parameter_with_brands(parameter) -> list:
    """`str(p)` per parameter, plus the marks `*` (keyword-only before it) and `/` (positional-only
    before it) at the place where Python requires them in the signature.

    Until 0.22.0 `signature()` assembled the parameters individually and lost both marks:
    `(request, username, password, *, next='')` was stored as `(…, password, next='')` in the baseline.
    A `*` inserted later — every call `login_password(r, u, p, "/start")` breaks
    — thus looked like no change (finding from step 3 of the tiering, M-1).
    """
    parts, star = [], any(p.kind is p.VAR_POSITIONAL for p in parameter)
    for i, p in enumerate(parameter):
        first_kw = i == 0 or parameter[i - 1].kind is not p.KEYWORD_ONLY
        if p.kind is p.KEYWORD_ONLY and not star and first_kw:
            parts.append("*")
        parts.append(str(p))
        if p.kind is p.POSITIONAL_ONLY and (i + 1 == len(parameter)
                                            or parameter[i + 1].kind is not p.POSITIONAL_ONLY):
            parts.append("/")
    return parts


def signature(fn) -> str:
    """The signature without `self` — parameter names and order are part of the promise.

    Whether a parameter is keyword-only is captured too: That is exactly what the break in 0.15 hinged on
    (`require_role("editor", True)` once meant `mfa=True` and would afterwards have been a second role).
    Really so since 0.22.0: with the marks `*` and `/` (`parameter_with_brands`).
    """
    try:
        s = inspect.signature(fn)
    except (TypeError, ValueError):
        return "?"
    parts = parameter_with_brands([p for name, p in s.parameters.items() if name != "self"])
    # The return type belongs to it. Without it `-> dict` could silently change to `-> str`:
    # every call breaks, and the guard would stay silent — it only covered the inputs.
    back = "" if s.return_annotation is inspect.Signature.empty else \
        f" -> {inspect.formatannotation(s.return_annotation)}"
    return "(" + ", ".join(parts) + ")" + back


def surface() -> dict:
    """What an embedder uses: the class, the configuration, the exports."""
    # Measuring is not using: `getmembers` reads every attribute, including the constant aliases
    # of tier C, and those warn when read. Method aliases deliver their wrapper here — its
    # signature is that of the target via `__wrapped__`, and that is exactly what is promised.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        manager = {name: signature(fn)
                   for name, fn in inspect.getmembers(TinySesam, callable)
                   if not name.startswith("_")}
    # With DEFAULT VALUE. Without it `session_ttl_hours` could silently change from 168 to 1 —
    # a behaviour break for everyone who never touched the field, and exactly the kind that
    # nobody looks for in the CHANGELOG. Until 0.18.0 the guard only covered name and type.
    fields = {}
    for f in TinySesamConfig.__dataclass_fields__.values():
        if f.default is not dataclasses.MISSING:
            default = repr(f.default)
        elif f.default_factory is not dataclasses.MISSING:   # type: ignore[misc]
            try:
                default = repr(f.default_factory())          # type: ignore[misc]
            except Exception:
                default = "<factory>"
        else:
            default = "<required>"
        fields[f.name] = f"{f.type} = {default}"
    presets = {name: signature(fn)
               for name, fn in inspect.getmembers(TinySesamConfig, callable)
               if not name.startswith("_")}
    exports = sorted(getattr(_package, "__all__", None)
                     or [n for n in dir(_package) if not n.startswith("_")])
    # Public class attributes belong to it. `inspect.getmembers(…, callable)` only captures
    # callables — `FORWARD_HEADERS_DEFAULT` could silently change that way, although the docs
    # list it as a commitment ("the Authelia-style set Remote-User/-Name/-Email/-Groups"). A
    # change breaks every Caddy/Traefik installation without a single line of code looking different.
    # A constant alias (tier C) is measured with the value of its target — read statically,
    # without triggering it; a method alias is listed above with the methods.
    constants = {}
    for name, value in vars(TinySesam).items():
        if isinstance(value, Deprecated):
            if value.method:
                continue
            value = vars(TinySesam)[value.destination]
        elif callable(value) or isinstance(value, (property, staticmethod, classmethod)):
            continue
        if not name.startswith("_"):
            constants[name] = repr(value)
    # Properties belong to it as well (0.20.1): `session_cookie_name`, `csrf_cookie_name`,
    # `resource_cookie_name` are the documented replacement API for fixed cookie names. What is
    # captured is the return type of the getter; a setter appends "(writable)". Read statically:
    # a property is the property object even then, and no constant alias warns in the process.
    properties = {name: signature(value.fget) + (" (schreibbar)" if value.fset else "")
                     for name, value in inspect.getmembers_static(
                         TinySesam, lambda w: isinstance(w, property))
                     if not name.startswith("_")}
    sources = CT.read_sources()
    return {"TinySesam": manager, "TinySesam.constants": constants,
            "TinySesam.properties": properties,
            "TinySesamConfig.fields": fields,
            "TinySesamConfig.methods": presets, "exports": exports,
            **{name: result_type_surface(type_name) for name, type_name in RESULT_TYPES.items()},
            **contract_surface(sources)}


def contract_surface(sources: dict) -> dict:
    """The contract beyond the Python names (PO decision 2026-10-29): the attributes `auth.cfg` and
    `auth.on_security_event`, the HTTP routes and the proxy-facing responses, the logger names and the
    security-log lines that filters read. Measured in `tests/_contract.py` (source) and
    `tests/_contract_probe.py` (probe instances). Related to — and not repeating — `check_values`: that one checks
    the LANGUAGE of the payload keys, this one pins WHICH keys there are."""
    return {
        "TinySesam.attributes": {"cfg": PR.cfg_attribute(),
                                 "on_security_event": f"{CT.hook_annotation(sources)}; {PR.hook_contract()}"},
        "TinySesam.event_payload": CT.event_payload(sources),
        "http.routes": CT.routes_static(sources),
        "http.forward": PR.forward_scenarios(),
        "http.contract": CT.contract_atoms(sources),
        "log.loggers": CT.loggers_static(sources),
        "log.lines": CT.log_atoms(sources, security.NOT_LOGIN_METHODS),
    }


def result_type_surface(type_name=LoginResult) -> dict:
    """A result type of the building blocks for custom pages (0.22.0, tier A): fields, methods, reasons.

    The guard captures the exports by name only. For `LoginResult` that is not enough: Whoever reads
    `result.next_factor` or checks `result.reason == "locked"` breaks on a
    renamed field or a dropped reason just as on a renamed method.
    Fields with type and default (like the configuration), methods with signature, `REASONS` with the
    value. The same holds for `PasswordChangeResult` (`result.api_keys_active`).
    """
    result = {}
    for f in dataclasses.fields(type_name):
        default = "<required>" if f.default is dataclasses.MISSING else repr(f.default)
        result[f.name] = f"{f.type} = {default}"
    result.update({name: signature(fn) for name, fn in inspect.getmembers(type_name, inspect.isfunction)
                     if not name.startswith("_")})
    result["REASONS"] = repr(type_name.REASONS)
    return result


class WithoutBrands(str):
    """A signature from a baseline from before 0.22.0: measured WITHOUT the marks `*` and `/`.

    Where the marks were, such an entry no longer knows. `assess()` therefore compares it
    with today's measurement without marks (`without_brands`) — otherwise a comparison with an
    older release would report every method with keyword-only parameters as a break, and a real
    one would be lost in it. A difference in names, order, defaults or return stays one.
    """


def without_brands(sig: str) -> str:
    """`(a, *, b=1) -> 'x'` → `(a, b=1) -> 'x'` — the form in which measurements were taken before 0.22.0."""
    rest = _bracket_and_rest(sig)[1]
    return ("(" + ", ".join(t for t in parts(sig) if t not in ("*", "/")) + ")"
            + (" " + rest if rest else ""))


def measurement(file: dict) -> dict:
    """Reduce the baseline to the pure measurement — the form `surface()` delivers.

    Also tolerates the baseline from before 0.22.0 (value as string, exports as list): A
    comparison with an older release (`git show v0.21.0:tests/api_surface.json`) should not fail on
    the form. Its signatures came without the marks `*`/`/` — they are read in as
    `WithoutBrands` and compared without marks.
    """
    result = {}
    for area, entries in file.items():
        if isinstance(entries, list):
            result[area] = sorted(entries)
            continue
        key_name = MEASURED_VALUE.get(area)
        if key_name is None:
            result[area] = sorted(entries)
            continue
        result[area] = {name: (e[key_name] if isinstance(e, dict)
                                    else WithoutBrands(e) if key_name == "sig" else e)
                             for name, e in entries.items()}
    return result


def with_tiers(now: dict, earlier: dict) -> dict:
    """The new baseline: measured values from `now`, every decision from `earlier`.

    Everything on the old entry except the measured value is carried over — the `tier`, later also
    alias details —, and only for the same name in the same area. A new name gets
    NO tier: The guard then reports it instead of silently committing to it.
    """
    storage = {}
    for area, measured in now.items():
        old = earlier.get(area, {})
        if isinstance(old, list):                     # form before 0.22.0: no decisions
            old = {}
        key_name = MEASURED_VALUE[area]
        new = {}
        for name in (measured if key_name is None else sorted(measured)):
            before = old.get(name)
            entry = ({k: v for k, v in before.items() if k != key_name}
                       if isinstance(before, dict) else {})
            if key_name is not None:
                entry[key_name] = measured[name]
            new[name] = entry
        storage[area] = new
    return storage


def tiers_from(file: dict) -> dict:
    """{area: {name: tier}} — only entries that carry one."""
    return {area: {name: e["tier"] for name, e in entries.items()
                      if isinstance(e, dict) and "tier" in e}
            for area, entries in file.items() if isinstance(entries, dict)}


def without_tier(file: dict) -> list:
    """Every entry without a valid tier, as a readable line. Empty = everything tiered."""
    missing = []
    for area in sorted(file):
        entries = file[area]
        if not isinstance(entries, dict):
            missing.append(f"{area}: whole list without tiers (form before 0.22.0)")
            continue
        for name in sorted(entries):
            e = entries[name]
            tier = e.get("tier") if isinstance(e, dict) else None
            if tier is None:
                missing.append(f"{area}.{name}: no tier")
            elif tier not in TIERS:
                missing.append(f"{area}.{name}: unknown tier {tier!r} "
                             f"(allowed: {', '.join(TIERS)})")
    return missing


def _bracket_and_rest(sig: str) -> tuple:
    """`(a, b) -> 'bool'` → (`a, b`, ` -> 'bool'`). Until T-13 `parts()` simply cut off the
    first and last character — for a signature WITH a return type that ended up in the
    last parameter, and a harmlessly appended parameter counted as a BREAK."""
    s, depth = sig.strip(), 0
    for i, c in enumerate(s):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return s[1:i], s[i + 1:].strip()
    return s[1:-1], ""


def parts(sig: str) -> list:
    """Split a signature string into parameters — only at commas outside brackets."""
    content = _bracket_and_rest(sig)[0]
    parts, depth, current = [], 0, ""
    for c in content:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += c
    if current.strip():
        parts.append(current.strip())
    return parts


def only_extended(old: str, new: str) -> bool:
    """Is the new signature callable like the old one?

    A parameter appended at the end WITH a default breaks nothing — every existing
    call keeps working. Reporting that as a break would not only be wrong, it would be harmful:
    A guard that cries wolf at harmless things gets clicked away, and then the real one is overlooked.
    """
    a, n = parts(old), parts(new)
    if _bracket_and_rest(old)[1] != _bracket_and_rest(new)[1]:
        return False                                  # different return type
    if len(n) < len(a) or n[:len(a)] != a:
        return False
    return all("=" in p or p.startswith("*") for p in n[len(a):])


def assess(old: dict, new: dict, tiers: "dict | None" = None):
    """(breaks, extensions) — both with a readable description.

    With `tiers` (from `tiers_from()` of the old baseline) every break starts with the tier of the
    name, `[A] …`: Whether the 1.0 clock jumps back depends on that alone.
    """
    breaks, extensions = [], []

    def brand(area, name):
        if tiers is None:
            return ""
        return f"[{tiers.get(area, {}).get(name, '?')}] "

    for area in sorted(set(old) | set(new)):
        a, n = old.get(area, {}), new.get(area, {})
        if isinstance(a, list) or isinstance(n, list):
            gone = sorted(set(a) - set(n))
            to_it = sorted(set(n) - set(a))
            breaks += [f"{brand(area, x)}{area}: '{x}' is gone" for x in gone]
            extensions += [f"{area}: '{x}' is new" for x in to_it]
            continue
        for name in sorted(set(a) - set(n)):
            breaks.append(f"{brand(area, name)}{area}.{name} is gone "
                           "(removed or renamed)")
        for name in sorted(set(n) - set(a)):
            extensions.append(f"{area}.{name} is new")
        for name in sorted(set(a) & set(n)):
            now = n[name]
            if isinstance(a[name], WithoutBrands) and isinstance(now, str):
                now = without_brands(now)        # old baseline: measured without `*`/`/`
            if a[name] == now:
                continue
            if isinstance(a[name], list) and isinstance(now, list):
                # A set of names (parameters of a route, keys of a payload): losing one breaks whoever
                # reads it, gaining one breaks nobody.
                gone, to_it = sorted(set(a[name]) - set(now)), sorted(set(now) - set(a[name]))
                if gone:
                    breaks.append(f"{brand(area, name)}{area}.{name}: lost {', '.join(gone)}")
                if to_it:
                    extensions.append(f"{area}.{name}: gained {', '.join(to_it)}")
                continue
            line = (f"{area}.{name}:\n        before {a[name]}\n        now    {n[name]}")
            if isinstance(a[name], str) and a[name].startswith("(") and only_extended(a[name], now):
                extensions.append(line + "\n        (only appended, with default value — "
                                            "existing calls keep working)")
            else:
                breaks.append(brand(area, name) + line)
    return breaks, extensions


#: These properties MUST be in the surface — the CHANGELOG of 0.20.0 sends every
#: embedding app to them ("read the CSRF cookie name from `auth.csrf_cookie_name`").
REQUIRED_PROPERTIES = ("session_cookie_name", "csrf_cookie_name", "resource_cookie_name")


def self_check(now: dict) -> None:
    """Does the guard measure the properties at all? (0.20.1)

    Until 0.20.0 `surface()` explicitly excluded them (`isinstance(value, property)`), and
    `getmembers(…, callable)` does not see them anyway. Renaming `csrf_cookie_name` —
    exactly the name that custom JS and custom routes need — thus went unnoticed by every guard.
    Also runs before `--update`: Otherwise the exclusion could be checked in together with the new dump.
    (Mutation probe: delete the area `TinySesam.properties` in `surface()` → red.)
    """
    own = now.get("TinySesam.properties", {})
    missing = [n for n in REQUIRED_PROPERTIES if n not in own]
    assert not missing, f"Properties missing from the frozen surface: {missing}"
    # Counter-check on the comparison itself: A renamed property is a BREAK, not an extension.
    renamed = json.loads(json.dumps(now))
    renamed["TinySesam.properties"]["csrf_cookie"] = \
        renamed["TinySesam.properties"].pop("csrf_cookie_name")
    breaks, _ = assess(now, renamed)
    assert any("csrf_cookie_name is gone" in b for b in breaks), breaks
    ok(f"Properties frozen ({len(own)}), renaming one would count as a break")


def self_check_signature(now: dict) -> None:
    """Does `signature()` measure the marks `*` and `/`, and report an inserted `*` as a break? (0.22.0)

    In addition: A baseline from before 0.22.0 (measured without marks) can still be compared — without
    every method with keyword-only parameters appearing as a break, and without a
    real difference disappearing in it. Also runs before `--update`.
    """
    def probe(self, a, /, b, *, c=1, d: "int" = 2) -> bool:   # noqa: ARG001
        return True

    def with_args(self, a, *rest, c=1, **kw):                   # noqa: ARG001
        return None

    assert signature(probe) == "(a, /, b, *, c=1, d: 'int' = 2) -> bool", signature(probe)
    assert signature(with_args) == "(a, *rest, c=1, **kw)", signature(with_args)
    assert signature(lambda *, x: x) == "(*, x)", signature(lambda *, x: x)
    sig = now["TinySesam"]["login_password"]
    assert ", *, next: " in sig, f"login_password measured without `*`: {sig}"
    # `API.md` shows the same signature (own copy in scripts/_api_docs.py, where the
    # marks were missing just the same).
    import importlib.util
    spec = importlib.util.spec_from_file_location("_api_doku_probe",
                                                  os.path.join(ROOT, "scripts", "_api_docs.py"))
    docs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(docs)
    for fn in (probe, with_args, TinySesam.login_password, TinySesamConfig.oidc_gateway):
        assert docs.signature(fn) == signature(fn), (fn, docs.signature(fn), signature(fn))
    # A `*` (or `/`) inserted later breaks every positional call.
    before = {"TinySesam": {"m": "(request, username, next='')"}}
    for afterwards in ("(request, username, *, next='')", "(request, /, username, next='')"):
        breaks, _ = assess(before, {"TinySesam": {"m": afterwards}})
        assert breaks and "TinySesam.m:" in breaks[0], (afterwards, breaks)
    assert only_extended("(a, b=1)", "(a, b=1, *, c=2)"), "kw-only with a default at the end is harmless"
    assert not only_extended("(a, *, b=1)", "(a, *, b=1, c)"), "kw-only WITHOUT a default breaks"
    # Old baseline (form before 0.22.0): read in without marks and compared without marks.
    old = measurement({"TinySesam": {"m": "(request, username, next='') -> 'x'",
                                 "n": "(request, next='')"}, "exports": ["TinySesam"]})
    assert isinstance(old["TinySesam"]["m"], WithoutBrands)
    new = {"TinySesam": {"m": "(request, username, *, next='') -> 'x'",
                         "n": "(request, *, weiter='')"}, "exports": ["TinySesam"]}
    breaks, expected = assess(old, new)
    assert len(breaks) == 1 and breaks[0].startswith("TinySesam.n:") and not expected, (breaks, expected)
    ok("Signatures with `*` and `/`: an inserted `*` is a break, a baseline from before 0.22.0 "
       "compares without marks")


def self_check_tiers(now: dict) -> None:
    """Does the tier requirement trigger, and does `--update` really assign no tier? (0.22.0)

    On synthetic baselines made from the real measurement, so that the check does not depend on the
    checked-in file, which may happen to be complete. Also runs before `--update`.
    """
    assert set(MEASURED_VALUE) == set(now), (
        f"Areas without a measured-value key: {sorted(set(now) - set(MEASURED_VALUE))} — "
        "add to MEASURED_VALUE, otherwise the baseline does not know what was measured and what was decided")
    total = sum(len(v) for v in now.values())
    # 1. Freshly measured, NO entry carries a tier — every single one is reported.
    raw = with_tiers(now, {})
    assert len(without_tier(raw)) == total, (len(without_tier(raw)), total)
    # 2. Everything tiered → nothing reported; an unknown tier (also lowercase) → reported.
    full = json.loads(json.dumps(raw))
    for entries in full.values():
        for e in entries.values():
            e["tier"] = "A"
    assert without_tier(full) == [], without_tier(full)
    for area, wrong in (("TinySesam", "a"), ("exports", "D")):
        broken = json.loads(json.dumps(full))
        name = sorted(broken[area])[0]
        broken[area][name]["tier"] = wrong
        assert any(f"{area}.{name}: unknown tier" in z for z in without_tier(broken)), wrong
        del broken[area][name]["tier"]
        assert f"{area}.{name}: no tier" in without_tier(broken), area
    # 3. `--update` carries decisions over, re-measures, and a new name stays without a tier.
    earlier = json.loads(json.dumps(full))
    method = sorted(earlier["TinySesam"])[0]
    earlier["TinySesam"][method].update(tier="B", sig="(stale)", replacement="new_name")
    del earlier["TinySesam"][sorted(earlier["TinySesam"])[1]]      # "new" since the old baseline
    del earlier["exports"][sorted(earlier["exports"])[0]]
    earlier["TinySesam"]["gone_for_long"] = {"sig": "()", "tier": "A"}
    new = with_tiers(now, earlier)
    assert new["TinySesam"][method] == {"sig": now["TinySesam"][method], "tier": "B",
                                         "replacement": "new_name"}, new["TinySesam"][method]
    assert "gone_for_long" not in new["TinySesam"]
    assert without_tier(new) == [f"TinySesam.{sorted(now['TinySesam'])[1]}: no tier",
                               f"exports.{sorted(now['exports'])[0]}: no tier"], without_tier(new)
    # 4. The baseline leads back to the measurement losslessly — otherwise `assess` would compare apples.
    assert measurement(new) == now
    # 5. A break names the tier of the name.
    away = json.loads(json.dumps(now))
    del away["TinySesam"][method]
    breaks, _ = assess(now, away, tiers_from(new))
    assert breaks and breaks[0].startswith(f"[B] TinySesam.{method} is gone"), breaks
    # 6. The normal run — the same function `main()` executes — is red as soon as ONE name
    #    has no tier, even if nothing about the measurement changed.
    red, missing, b, e = compare(full, now)
    assert (red, missing, b, e) == (False, [], [], []), (red, missing, b, e)
    gap = json.loads(json.dumps(full))
    del gap["TinySesam.properties"]["csrf_cookie_name"]["tier"]
    red, missing, b, e = compare(gap, now)
    assert red and missing == ["TinySesam.properties.csrf_cookie_name: no tier"] \
        and not b and not e, (red, missing, b, e)
    ok(f"Tier requirement works ({total} names): missing and unknown tier reported, "
       "`--update` assigns none")


def compare(earlier_file: dict, now: dict) -> tuple:
    """(red, without_tier, breaks, extensions) — the whole decision of the normal run.

    A function of its own, so that the self-check checks exactly what `main()` executes: A
    tier check that existed only in the self-check would run into the void in the real run.
    """
    missing = without_tier(earlier_file)
    breaks, extensions = assess(measurement(earlier_file), now, tiers_from(earlier_file))
    return bool(missing or breaks or extensions), missing, breaks, extensions


# ---------- Tier C: the aliases (0.22.0) ----------
# PO decision 2026-09-26: A tier-C name gets a leading underscore; the old name
# stays as an alias until 1.0 that triggers a DeprecationWarning when called. That is only
# true if it is measured — an alias that silently forwards, or a route that still calls the
# old name (and thus warns on every login), would look just as green.

#: Where code lives that belongs to the package or uses it without being a test: No old
#: name appears there. The tests call the underscore names; only this guard calls the old ones.
OWN_CODE = ("tinysesam", "examples", "scripts", "web")
#: Under these areas a name may carry tier C — only there is there an alias.
C_AREAS = {"TinySesam": True, "TinySesam.constants": False}   # area → method?


def c_entries(file: dict) -> dict:
    """{(area, name): entry} — every tier-C entry, in whichever area."""
    return {(area, name): e for area, entries in file.items()
            if isinstance(entries, dict)
            for name, e in entries.items() if isinstance(e, dict) and e.get("tier") == "C"}


def _warns(klass, name: str, alias: Deprecated) -> list:
    """Does the alias warn exactly once, with replacement and at the caller — and does it forward?

    On an object without constructor whose target is a stub: This is how the guard measures the alias
    itself, not what the real method would do with test data."""
    error = []
    probe = klass.__new__(klass)
    char, received = object(), []
    with warnings.catch_warnings(record=True) as warned:
        warnings.simplefilter("always")
        if alias.method:
            probe.__dict__[alias.destination] = lambda *a, **k: (received.append((a, k)), char)[1]
            fn = getattr(probe, name)
            if warned:
                error.append("warns already on lookup (hasattr, getmembers) instead of on call")
                del warned[:]
            result = fn(1, two=2)
            if result is not char or received != [((1,), {"two": 2})]:
                error.append(f"does not pass through unchanged to {alias.destination} "
                              f"(received {received!r})")
        else:
            result = getattr(klass, name)
            if result is not vars(klass)[alias.destination]:
                error.append(f"does not return the value of {alias.destination}")
    if len(warned) != 1:
        error.append(f"raises {len(warned)} warnings instead of exactly one")
    for w in warned[:1]:
        text = str(w.message)
        if w.category is not DeprecationWarning:
            error.append(f"warns as {w.category.__name__}, not as DeprecationWarning")
        if os.path.abspath(w.filename) != os.path.abspath(__file__):
            error.append(f"the warning points to {os.path.basename(w.filename)} instead of to the "
                          "caller (stacklevel)")
        for part in (f"{klass.__name__}.{name} ", f"goes away with {UNTIL}", alias.replacement):
            if part not in text:
                error.append(f"the message does not name {part!r}: {text!r}")
    return [f"TinySesam{'' if alias.method else '.constants'}.{name}: Alias {f}" for f in error]


def _assignment(klass, name: str, alias: Deprecated) -> list:
    """An assignment to the old name on the object (test fake) no longer takes effect — does it warn?

    Exactly one `RuntimeWarning` (visible without a filter) that names the target and points to the assignment;
    afterwards the old name reads the assigned value, and `del` restores the alias
    (this is how `mock.patch.object` cleans up). Finding of the counter-check 2026-09-27: A fake on
    `check_password` was called 0 times, the login gave 303, and nobody warned."""
    error = []
    probe = klass.__new__(klass)
    fake = object()
    with warnings.catch_warnings(record=True) as warned:
        warnings.simplefilter("always")
        try:
            setattr(probe, name, fake)
            read = probe.__dict__.get(name, None) is fake and getattr(probe, name) is fake
            delattr(probe, name)
        except Exception as e:                     # noqa: BLE001 — every exception is a finding
            return [f"TinySesam.{name}: Alias: assignment on the object raises {type(e).__name__}: {e}"]
    if [w.category for w in warned] != [RuntimeWarning]:
        error.append(f"assignment on the object raises {[w.category.__name__ for w in warned]} "
                      "instead of exactly one RuntimeWarning")
    else:
        text = str(warned[0].message)
        if f"`{alias.destination}`" not in text:
            error.append(f"the warning on an assignment does not name the target `{alias.destination}`: "
                          f"{text!r}")
        if os.path.abspath(warned[0].filename) != os.path.abspath(__file__):
            error.append(f"the warning on an assignment points to "
                          f"{os.path.basename(warned[0].filename)} instead of to the assignment")
    if not read:
        error.append("does not return the assigned value after an assignment on the object")
    if name in probe.__dict__:
        error.append("`del` leaves the value set on the object in place")
    kind = "" if alias.method else ".constants"
    return [f"TinySesam{kind}.{name}: Alias {f}" for f in error]


def alias_findings(file: dict, klass=TinySesam) -> list:
    """Do baseline and class agree for tier C, and does every alias do what it should?"""
    findings = []
    tier = {(b, n): e.get("tier") for b, ee in file.items() if isinstance(ee, dict)
             for n, e in ee.items() if isinstance(e, dict)}
    c = c_entries(file)
    for (area, name), e in sorted(c.items()):
        if area not in C_AREAS:
            findings.append(f"{area}.{name}: tier C exists only for methods and constants "
                           "of the class — there as an alias")
            continue
        alias = inspect.getattr_static(klass, name, None)
        if not isinstance(alias, Deprecated):
            kind = "is missing in the class" if alias is None else "has its own implementation"
            findings.append(f"{area}.{name}: tier C, {kind} — the implementation is called "
                           f"`_{name}`, the old name becomes `Deprecated(\"_{name}\", \"<Ersatz>\")`")
            continue
        if alias.method != C_AREAS[area]:
            findings.append(f"{area}.{name}: the alias points to "
                           f"{'a method' if alias.method else 'a constant'}")
        if e.get("target") != alias.destination:
            findings.append(f"{area}.{name}: the baseline names `target` {e.get('target')!r}, the "
                           f"alias points to {alias.destination!r}")
        destination = inspect.getattr_static(klass, alias.destination, None)
        if destination is None or isinstance(destination, Deprecated):
            findings.append(f"{area}.{name}: the target {alias.destination!r} is not an implementation")
        elif alias.destination != f"_{name}" and tier.get((area, alias.destination)) != "A":
            findings.append(f"{area}.{name}: points to {alias.destination!r} — allowed is `_{name}` "
                           "or a name of tier A (e.g. `complete_mfa` → `complete_totp`)")
        if not e.get("since") or e.get("until") != alias.until:
            findings.append(f"{area}.{name}: `since`/`until` are missing or do not match the alias "
                           f"(baseline {e.get('since')!r}/{e.get('until')!r}, alias until {alias.until})")
        findings += _warns(klass, name, alias) + _assignment(klass, name, alias)
    for name, alias in sorted(vars(klass).items()):
        if isinstance(alias, Deprecated):
            area = "TinySesam" if alias.method else "TinySesam.constants"
            if (area, name) not in c:
                findings.append(f"{area}.{name}: is an alias (Deprecated) in the class, but in the "
                               "baseline not tier C")
    return findings


def old_names_in_text(text: str, destinations: dict, strings: bool) -> list:
    """[(line, finding)] — accesses to an old name in a source text (AST, not grep:
    a comment or docstring that mentions the name is not a call)."""
    hit = []
    for k in ast.walk(ast.parse(text)):
        if isinstance(k, ast.Attribute) and k.attr in destinations:
            hit.append((k.lineno, f"`.{k.attr}` is the old name — use `.{destinations[k.attr]}`"))
        elif (strings and isinstance(k, ast.Constant) and isinstance(k.value, str)
              and k.value in destinations):
            hit.append((k.lineno, f"string {k.value!r} — getattr/setattr on the old "
                                      f"name? use `{destinations[k.value]}`"))
    return sorted(hit)


def internal_calls(destinations: dict, root: str = ROOT) -> tuple:
    """(findings, checked files) — does code in the repo that is not a test use an old name?

    Strings only count in the package itself (`security.OWN_LOCK` names methods by
    name); `scripts/_api_docs.py` may name the old names — it describes them."""
    findings, number = [], 0
    for folder in OWN_CODE:
        for path_, under, files in os.walk(os.path.join(root, folder)):
            under[:] = sorted(u for u in under if u != "__pycache__")
            for file in sorted(files):
                if not file.endswith(".py"):
                    continue
                path = os.path.join(path_, file)
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                number += 1
                rel = os.path.relpath(path, root)
                findings += [f"{rel}:{z}: {was}"
                            for z, was in old_names_in_text(text, destinations, folder == "tinysesam")]
    return findings, number


def _version(text: str) -> tuple:
    numbers = []
    for part in str(text).split(".")[:3]:
        digits = ""
        for char in part:
            if not char.isdigit():
                break
            digits += char
        numbers.append(int(digits or 0))
    return tuple(numbers + [0] * (3 - len(numbers)))


def deadline_findings(file: dict, version: str) -> list:
    """With 1.0 the aliases fall — if one is still there, that is red, not forgotten."""
    return [f"{area}.{name}: the alias should have fallen with {e.get('until', UNTIL)} "
            f"(version {version}) — remove alias and entry, CHANGELOG Removed"
            for (area, name), e in sorted(c_entries(file).items())
            if _version(version) >= _version(e.get("until", UNTIL))]


#: The name of the still-open section in the CHANGELOG — what is in it is in no release.
OPEN = "Unreleased"


def changelog_stale(text: str) -> list:
    """[(section, {names})] in CHANGELOG order (newest first): per section
    `## [X.Y.Z]` or `## [Unreleased]` the names in backticks under `### Deprecated`."""
    sections, current, in_stale = [], None, False
    for line in text.split("\n"):
        if line.startswith("## ["):
            head = line[4:].split("]", 1)[0].strip()
            current = (head, set())
            sections.append(current)
            in_stale = False
        elif line.startswith("### "):
            in_stale = current is not None and line[4:].strip().startswith("Deprecated")
        elif in_stale:
            parts = line.split("`")
            current[1].update(t for t in parts[1::2] if t.isidentifier())
    return sections


def since_findings(file: dict, changelog: str) -> list:
    """Does the `since` of every alias match the release that introduces it? (0.22.0)

    Reason: The tiering was built with `seit: 0.21.0`, then 0.21.0 went out without it. A
    `since` that names an already published release in which the alias did not exist
    sends everyone who reads the warning to the wrong version — and nothing was noticed, because
    only whether the field is there was checked. The rule, measured against the CHANGELOG:

    * The alias is under `### Deprecated` in exactly the section that introduces it — the
      oldest that names it there. If it is missing everywhere, that is red.
    * If `[Unreleased]` introduces it, `since` must be **greater** than the latest release
      in the CHANGELOG: The next release brings it, none of those already out.
    * If a release `[X.Y.Z]` introduces it, `since` must be exactly `X.Y.Z`. When renaming
      `[Unreleased]` to the new release the same rule keeps applying.
    """
    sections = changelog_stale(changelog)
    releases = [head for head, _ in sections if head != OPEN and head[:1].isdigit()]
    if not releases:
        return ["CHANGELOG.md: no release section `## [X.Y.Z]` found — the `since` of the aliases "
                "cannot be checked"]
    youngest = max(releases, key=_version)
    findings = []
    for (area, name), e in sorted(c_entries(file).items()):
        since = str(e.get("since") or "")
        where = [head for head, names in sections if name in names]
        if not where:
            findings.append(f"{area}.{name}: CHANGELOG lists the alias in no section under "
                           f"Deprecated — it belongs there, with replacement (`since` {since!r})")
            continue
        introduction = where[-1]                   # the oldest section that names it
        if introduction == OPEN:
            if _version(since) <= _version(youngest):
                findings.append(
                    f"{area}.{name}: `since` {since!r}, but the alias is only under "
                    f"[{OPEN}] — {youngest} is already published and did not know it; "
                    f"set `since` to the next release (greater than {youngest})")
        elif _version(since) != _version(introduction):
            findings.append(f"{area}.{name}: `since` {since!r}, but the alias was introduced by "
                           f"[{introduction}] (CHANGELOG, Deprecated)")
    return findings


def c_findings(file: dict, klass=TinySesam, version: str = _package.__version__,
              root: str = ROOT, changelog: "str | None" = None) -> tuple:
    """(findings, checked files) — the whole tier-C check of the normal run."""
    destinations = {name: alias.destination for name, alias in vars(klass).items() if isinstance(alias, Deprecated)}
    destinations.update({name: e.get("target") or f"_{name}" for (_, name), e in c_entries(file).items()
                  if name not in destinations})
    inside, number = internal_calls(destinations, root)
    if changelog is None:
        with open(os.path.join(root, "CHANGELOG.md"), encoding="utf-8") as fh:
            changelog = fh.read()
    return (alias_findings(file, klass) + inside + deadline_findings(file, version)
            + since_findings(file, changelog)), number


def check_subclass() -> None:
    """A subclass that overrides an old name must find out (RuntimeWarning):
    Since 0.22.0 the routes call `_name`, the override would silently run into the void."""
    with warnings.catch_warnings(record=True) as warned:
        warnings.simplefilter("always")

        class _Overrides(TinySesam):
            def check_password(self, username, password):
                return None

            def own_method(self):
                return None
    assert [w.category for w in warned] == [RuntimeWarning], [str(w.message) for w in warned]
    text = str(warned[0].message)
    assert f"{_Overrides.__name__}.check_password" in text and "`_check_password`" in text, text
    assert os.path.abspath(warned[0].filename) == os.path.abspath(__file__), warned[0].filename
    with warnings.catch_warnings(record=True) as warned:
        warnings.simplefilter("always")

        class _Harmless(TinySesam):
            def own_method(self):
                return None
    assert not warned, (_Harmless.__name__, [str(w.message) for w in warned])
    ok("a subclass that overrides an old name gets a RuntimeWarning")


def check_warning_filter() -> None:
    """Does `tests/run_all.py` really turn an old name, called FROM the package, into an error?

    A misspelled `-W` filter is only acknowledged by Python with "Invalid -W option ignored"
    — the run would stay green without checking anything. Hence measure the effect: In a
    fresh process with exactly the environment of a suite, code that poses as a module of the package
    calls an alias (method and constant) — that must raise; the same call from
    `__main__` (a user, a test) only warn."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import run_all
    import tempfile
    sandbox = tempfile.mkdtemp(prefix="tinysesam-warnfilter-")
    # Only the filter of run_all.py counts — an externally set PYTHONWARNINGS (such as a
    # strict run with `error::DeprecationWarning`) would falsify the counter-check from `__main__`.
    from_outside = os.environ.pop("PYTHONWARNINGS", None)
    try:
        environment = run_all.environment(sandbox)
    finally:
        if from_outside is not None:
            os.environ["PYTHONWARNINGS"] = from_outside
    entries = set(environment.get("PYTHONWARNINGS", "").split(","))
    module = set()
    for path_, under, files in os.walk(os.path.join(ROOT, "tinysesam")):
        under[:] = [u for u in under if u != "__pycache__"]
        parts = os.path.relpath(path_, ROOT).split(os.sep)
        module |= {".".join(parts if d == "__init__.py" else parts + [d[:-3]])
                   for d in files if d.endswith(".py")}
    missing = sorted(m for m in module if f"error:TinySesam.:DeprecationWarning:{m}" not in entries)
    assert not missing, f"run_all.py does not filter these modules: {missing}"
    probe = (
        "import warnings\n"
        "from tinysesam import TinySesam\n"
        "p = TinySesam.__new__(TinySesam)\n"
        "p.__dict__['_sec'] = lambda key: 1\n"
        "for code in ('p.sec(\"x\")', 'p.DEMO_USERS'):\n"
        "    for modul in ('tinysesam.router', '__main__'):\n"
        "        try:\n"
        "            exec(code, {'__name__': modul, 'p': p})\n"
        "            print(modul, 'warnt')\n"
        "        except DeprecationWarning:\n"
        "            print(modul, 'wirft')\n")
    r = subprocess.run([sys.executable, "-c", probe], cwd=ROOT, env=environment,
                       capture_output=True, text=True)
    import shutil
    shutil.rmtree(sandbox, ignore_errors=True)
    assert r.returncode == 0, r.stderr[-800:]
    assert "Invalid -W option" not in r.stderr, r.stderr[-800:]
    assert r.stdout.split("\n")[:4] == ["tinysesam.router wirft", "__main__ warnt"] * 2, r.stdout
    ok(f"run_all.py: an old name from the package raises ({len(module)} modules filtered), "
       "from own code it only warns")


def self_check_c() -> None:
    """Does every tier-C rule trigger? On a probe class, not on TinySesam — its aliases
    hopefully happen to be right, and a rule that was never red proves nothing."""
    import tempfile

    def klass(alias_type=Deprecated, real_f=False):
        ns = {"_f": lambda self, *a, **k: ("f", a, k), "_K": (1, 2),
              "g": lambda self: None, "K": alias_type("_K", "no replacement; internal")}
        ns["f"] = (lambda self: None) if real_f else alias_type("_f", "use `g` instead")
        return type("TinySesam", (), ns)

    def storage(**addition):
        e_f = {"sig": "()", "tier": "C", "target": "_f", "since": C_SINCE, "until": UNTIL}
        e_k = {"value": "(1, 2)", "tier": "C", "target": "_K", "since": C_SINCE, "until": UNTIL}
        d = {"TinySesam": {"f": e_f, "g": {"sig": "()", "tier": "A"}},
             "TinySesam.constants": {"K": e_k}, "exports": {}}
        for path, value in addition.items():
            area, name, slot = path.split("__")
            area = {"m": "TinySesam", "k": "TinySesam.constants", "x": "exports"}[area]
            entry = d[area].setdefault(name, {"tier": "C"})
            if value is None:
                entry.pop(slot, None)
            else:
                entry[slot] = value
        return d

    def red(findings, piece):
        assert any(piece in b for b in findings), (piece, findings)

    clean = alias_findings(storage(), klass())
    assert clean == [], clean

    class Silent(Deprecated):
        __slots__ = ()

        def _warn(self):
            pass

    class Deep(Deprecated):
        __slots__ = ()

        def _warn(self):
            warnings.warn(self.message, DeprecationWarning, stacklevel=2)

    class Swallowed(Deprecated):
        __slots__ = ()

        def __get__(self, obj, owner=None):
            fn = super().__get__(obj, owner)
            return (lambda *a, **k: fn(*a)) if self.method else fn

    class SilentAssignment(Deprecated):
        __slots__ = ()

        def __set__(self, obj, value):
            obj.__dict__[self.name] = value

    class Wrong(Deprecated):
        __slots__ = ()

        def __set__(self, obj, value):
            warnings.warn("veraltet", RuntimeWarning, stacklevel=2)
            obj.__dict__[self.name] = value

    class Elsewhere(Deprecated):
        __slots__ = ()

        def __set__(self, obj, value):
            warnings.warn_explicit(f"auf `{self.destination}` setzen", RuntimeWarning, "anderswo.py", 1)
            obj.__dict__[self.name] = value

    red(alias_findings(storage(), klass(SilentAssignment)),
        "TinySesam.f: Alias assignment on the object raises []")
    red(alias_findings(storage(), klass(Wrong)), "does not name the target `_f`")
    red(alias_findings(storage(), klass(Elsewhere)), "points to anderswo.py instead of to the assignment")
    red(alias_findings(storage(), klass(Silent)), "raises 0 warnings")
    red(alias_findings(storage(), klass(Deep)), "instead of to the caller")
    red(alias_findings(storage(), klass(Swallowed)), "does not pass through unchanged")
    red(alias_findings(storage(), klass(real_f=True)), "TinySesam.f: tier C, has its own")
    red(alias_findings(storage(m__f__tier="A"), klass()), "in the baseline not tier C")
    red(alias_findings(storage(m__f__target="_g"), klass()), "the baseline names `target` '_g'")
    red(alias_findings(storage(m__f__until=None), klass()), "`since`/`until` are missing")
    red(alias_findings(storage(x__New__tier="C"), klass()), "exports.New: tier C exists only")
    red(alias_findings(storage(m__h__target="_h"), klass()), "TinySesam.h: tier C, is missing")
    redirected = type("TinySesam", (), {"_f": lambda self: None, "g": lambda self: None,
                                        "_K": 1, "K": Deprecated("_K", "x"),
                                        "f": Deprecated("g", "use `g` instead")})
    assert alias_findings(storage(m__f__target="g"), redirected) == [], "target of tier A is allowed"
    red(alias_findings(storage(m__f__target="g", m__g__tier="B"), redirected), "allowed is `_f`")
    # Internal calls: AST over a probe repo — attribute everywhere, string only in the package.
    probe = tempfile.mkdtemp(prefix="tinysesam-c-")
    for rel, text in (("tinysesam/m.py", "auth.f(1)\nauth._f(2)\ngetattr(auth, 'f')\n# auth.f\n"),
                      ("examples/e.py", "x = 'f'\nauth.K\n"), ("tests/t.py", "auth.f()\n")):
        os.makedirs(os.path.join(probe, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(probe, rel), "w", encoding="utf-8") as fh:
            fh.write(text)
    inside, number = internal_calls({"f": "_f", "K": "_K"}, probe)
    assert number == 2 and sorted(b.split(": ")[0] for b in inside) == [
        "examples/e.py:2", "tinysesam/m.py:1", "tinysesam/m.py:3"], (number, inside)
    # Deadline: from 1.0 every remaining alias is red, before that none.
    assert deadline_findings(storage(), "0.22.0") == [] and deadline_findings(storage(), "0.99.3") == []
    assert len(deadline_findings(storage(), "1.0.0")) == 2 and deadline_findings(storage(), "1.2")

    # `since` against the CHANGELOG (0.22.0): The alias is under "Deprecated" in the section that
    # introduces it; in the open section `since` is greater than the latest release, otherwise exactly that one.
    def changelog(unclosed="", release=""):
        return ("# Changelog\n\n## [Unreleased]\n\n### Deprecated\n\n" + unclosed + "\n\n"
                "## [0.21.0] — 2026-09-27\n\n### Changed\n\n- `f` and `K` do not count here\n\n"
                "### Deprecated\n\n" + release + "\n\n## [0.20.1] — 2026-09-24\n")
    both = "- `f` → `_f`, `K` → `_K`"
    new = storage(m__f__since="0.22.0", k__K__since="0.21.1")
    assert since_findings(new, changelog(unclosed=both)) == [], since_findings(new, changelog(unclosed=both))
    red(since_findings(storage(m__f__since="0.21.0"), changelog(unclosed=both)),
        "TinySesam.f: `since` '0.21.0', but the alias is only under [Unreleased]")
    red(since_findings(storage(k__K__since="0.19.0"), changelog(unclosed=both)),
        "TinySesam.constants.K: `since` '0.19.0', but")
    old = storage(m__f__since="0.21.0", k__K__since="0.21.0")
    assert since_findings(old, changelog(release=both)) == []
    assert since_findings(old, changelog(unclosed=both, release=both)) == [], "the oldest counts"
    red(since_findings(storage(m__f__since="0.22.0"), changelog(release=both)),
        "TinySesam.f: `since` '0.22.0', but the alias was introduced by [0.21.0]")
    red(since_findings(storage(), changelog(unclosed="- `K` → `_K`")), "TinySesam.f: CHANGELOG lists")
    red(since_findings(storage(), "# Changelog\n\n## [Unreleased]\n"), "no release section")
    # The normal run goes through the same function and sees all four kinds.
    findings, _ = c_findings(storage(m__f__since="0.21.0", k__K__since="0.22.0"), klass(Silent),
                           "1.0.0", probe, changelog(unclosed=both))
    import shutil
    shutil.rmtree(probe, ignore_errors=True)
    for kind in ("raises 0 warnings", "tinysesam/m.py:1", "should have fallen", "did not know it"):
        red(findings, kind)
    ok("Tier-C rules trigger: silent alias, wrong stacklevel, swallowed arguments, "
       "silent assignment on the object, own implementation, baseline ≠ class, wrong target, "
       "internal call, deadline 1.0, `since` against the CHANGELOG")


# ---------- The names of tiers A and B: English (0.22.0) ----------
# PO decision 2026-09-27: The public surface is named in English — renamed before 0.22.0,
# **without an alias**, because the commitments of the tiers only begin with this release and no consumer
# used any of the German names (CHANGELOG, "Was beim Update auffällt"). So that no German
# word comes back, the guard measures the WHOLE surface of tiers A and B: every name of the
# baseline, the parameters of every method and function (on the live object), the configuration fields
# and the public attributes and constructor parameters of the exported error types
# (`ConfigError.field`, `MissingExtra(message, extra)`). Tier C stays out: Those are the
# old names that keep forwarding as aliases until 1.0. The keys and values this surface
# returns or accepts are measured, since the second PO decision of the same day, by `check_values()`
# further below; audit and log lines (`login_fail … grund=`, fail2ban) stay as they are.
# Section (k) in `tests/test_sign_in.py` additionally measures the surface of the login building block together with
# the values of `LoginResult.REASONS` — with the same word list (`german_in`).
# (Mutation probes: `by_operator` in `change_username` back to `through_operator` → red;
# `ConfigError.owner_id` back to `owner_id` → red; a configuration field `sperre_minuten`
# with a tier → red; emptying `STEM` → self-check red; no longer measuring the parameters → red.)

#: German words, as a WHOLE word of a name (split at `_`, `.` and CamelCase). Chosen with
#: care: none of them is also an English word that occurs in an API — `die`, `old`,
#: `has`, `was`, `man`, `also` are therefore missing, `series` only counts whole (otherwise `series` would be flagged).
GERMAN = frozenset("""
    abgeschaltet abmelden alle als andere anderen anmelden anmeldung antwort anwendung anzahl art arten
    aufheben auftrag ausfuehren basis bei benutzer besitzer bestaetigt betreiber bindung bis darf der
    durch eigene einrichten ereignis ereignisse ergebnis erlaubt erstfaktor falsch fehler fehlgriff
    feld felder fertig foederation foederiert foederierte freigabe frist fremde fuer gesperrt gewaehlt
    gruende grund gruppe gruppen gueltig jetzt kandidat kein keine kennung kennungen konto konten
    leer lesen liste loese loeschen mangel meldung methoden minuten mit nach nachbinden nachbindung
    nachricht naechster neu nur oder ohne passwort pfad praefix pruefen pruefung quelle quellen rolle
    rollen schluessel schreiben seit seite seiten sekunden selbst serie setzen sicherheit
    sicherheitsereignisse sitzung sitzungen sperre sperren sprache stunden tage ueberlauf und
    vergeben verzeichnis von weg weiter weiterleitung wert werte zahl zeit ziel zu zuordnung zurueck
    zweck
    abgewiesen anders ausgefuehrt automat dienstkonto gebunden konflikt lokal mehrdeutig mensch
    schon treffer verbleibend ja nein
""".split())
#: German word stems that are also conspicuous INSIDE a word: A constant like
#: `SECURITY_EVENTS` is ONE word after splitting. Only stems of five or more letters that are in
#: no English word (`binding` ≠ `binding`, `session`, `kennung` …).
STEM = ("anmeld", "aufheb", "ausfuehr", "benutzer", "besitzer", "bestaetig", "betreiber",
         "abgemeld", "bindung", "einricht", "ereignis", "ergebnis", "erstfaktor", "fehlgriff", "fehlserie",
         "foederi", "gesperrt", "gewaehlt", "gueltig", "kennung", "loesch", "nachricht", "passwort",
         "pruef", "schluessel", "sicherheit", "sitzung", "ueberlauf", "verworfen", "verzeichnis",
         "zuordnung")


def words(name: str) -> set:
    """`LoginResult` → {login, result}, `SECURITY_EVENTS` → {security, events}."""
    return {w for w in re.split(r"[_.]", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name)).lower())
            if w}


def german_in(name: str) -> set:
    """What is German in `name`: whole words from `GERMAN`, stems from `STEM` (also in the middle of a
    word) and umlauts/ß — empty if nothing. A set, so that the finding says WHAT stood out."""
    ww = words(name)
    hits = ww & GERMAN
    hits |= {s for s in STEM for w in ww if s in w}
    hits |= {z for z in str(name) if not z.isascii()}
    return hits


def _parameter(fn) -> list:
    """The parameter names of a method or function, without `self`/`cls` — `[]` if no
    signature is available (then `check_names` reports that via the minimum count)."""
    try:
        return [p for p in inspect.signature(fn).parameters if p not in ("self", "cls")]
    except (TypeError, ValueError):
        return []


def surface_names(file: dict, klass=TinySesam, config=TinySesamConfig,
                      package=_package) -> list:
    """[(where, name)] — every name of tiers A and B, plus parameters, fields, attributes.

    The names come from the baseline (the normal run keeps it equal to the measurement), the
    parameters and attributes from the live object — a new parameter needs no new
    entry to be seen."""
    names = []
    objects = {"TinySesam": klass, "TinySesamConfig.methods": config, **RESULT_TYPES}
    own = {klass.__name__, config.__name__, *RESULT_TYPES}   # have their own areas
    for area in sorted(file):
        entries = file[area]
        if not isinstance(entries, dict):
            continue
        for name in sorted(entries):
            e = entries[name]
            if not isinstance(e, dict) or e.get("tier") not in ("A", "B"):
                continue
            names.append((area, name))
            if area in objects:
                destination = inspect.getattr_static(objects[area], name, None)
                if isinstance(destination, (staticmethod, classmethod)):
                    destination = destination.__func__
                if inspect.isfunction(destination):
                    names += [(f"{area}.{name}()", p) for p in _parameter(destination)]
            elif area == "exports":
                obj = getattr(package, name, None)
                if inspect.isfunction(obj):
                    names += [(f"{name}()", p) for p in _parameter(obj)]
                elif inspect.isclass(obj) and name not in own:
                    attribute = {a for a in list(vars(obj)) + list(inspect.get_annotations(obj))
                                 if not a.startswith("_")}
                    names += [(name, a) for a in sorted(attribute)]
                    if "__init__" in vars(obj):
                        names += [(f"{name}()", p) for p in _parameter(vars(obj)["__init__"])]
    return names


def name_findings(names: list) -> list:
    """Every name with a German word, as a readable line. Empty = everything English."""
    return [f"{where}: {name!r} ({', '.join(sorted(german_in(name)))})"
            for where, name in names if german_in(name)]


#: What the measurement must see at minimum — otherwise it silently measures less than it promises
#: (an empty intersection looks like a clean surface).
NAMES_REQUIRED = (("TinySesam", "change_username"), ("TinySesam.change_username()", "by_operator"),
                 ("TinySesam.constants", "SECURITY_EVENTS"),
                 ("TinySesamConfig.fields", "federation_name_binding_days"),
                 ("TinySesamConfig.methods", "validate"), ("TinySesam.properties", "csrf_cookie_name"),
                 ("ConfigError", "owner_id"), ("MissingExtra()", "message"),
                 ("LoginResult", "next_factor"), ("PasswordChangeResult", "api_keys_active"),
                 ("exports", "current_version"))


def check_names(file: dict, klass=TinySesam, package=_package, required=NAMES_REQUIRED,
                 at_least=(500, 200, 150)) -> tuple:
    """(findings, count) — the whole name check of the normal run, with minimum count. The same
    function checks the self-probe; a check that existed only there would run into the void in the run."""
    names = surface_names(file, klass=klass, package=package)
    missing = [f"{where}: {name!r} is not measured — measurement broken?"
             for where, name in required if (where, name) not in names]
    parameter = sum(1 for where, _ in names if where.endswith("()"))
    fields = sum(1 for where, _ in names if where == "TinySesamConfig.fields")
    # As of 0.22.0: 596 entries, of which 278 parameters and 159 fields — with headroom downwards.
    if len(names) < at_least[0] or parameter < at_least[1] or fields < at_least[2]:
        missing.append(f"too little measured: {len(names)} names, {parameter} parameters, {fields} "
                     f"fields (expected at least {'/'.join(map(str, at_least))})")
    return missing + name_findings(names), len(names)


def self_check_names() -> None:
    """Does the name check find what it should find — and only that? On a probe, not on the
    real surface: That one is hopefully clean right now, and a list that never found anything
    proves nothing."""
    for german in ("foederation_nachbinden", "loese_fremde_bindung", "SICHERHEITSEREIGNISSE",
                    "andere_sitzungen", "api_key_art", "kennung_vergeben", "nach_der_antwort",
                    "nur_foederiert", "passwort_mangel", "pin_als_erstfaktor", "pruefen",
                    "sperre_aufheben", "FOEDERIERTE_QUELLEN", "MFA_ENROLLMENT_ARTEN",
                    "NACHBINDUNG_GRUENDE", "SEITEN", "durch_betreiber", "zuordnung", "ausfuehren",
                    "quelle", "neu", "kandidat", "email_bestaetigt", "jetzt", "basis", "auftrag",
                    "bei_ueberlauf", "methoden", "name_selbst_gewaehlt", "feld", "besitzer_id",
                    "nachricht", "pfad", "darf_mfa_einrichten", "SperreMinuten", "größe",
                    # keys and values up to 0.21.x (`check_values`, PO decision 2026-09-27):
                    "ausgefuehrt", "gebunden", "konflikt", "mehrdeutig", "nicht_im_verzeichnis",
                    "ohne_kennung", "abgewiesen", "lokal", "verzeichnis", "gebunden_an", "treffer",
                    "grund", "kein_konto", "dienstkonto", "gesperrt", "schon_gebunden",
                    "anders_gebunden", "adresse_als_name", "kennung_ungueltig", "name_aus_quelle",
                    "frist", "fehlserien", "verworfene_rollen", "verbleibend", "anzahl",
                    "recovery_codes_geloescht", "automat", "mensch", "praefix", "zweck", "vergeben",
                    "sperre", "admin_passwort", "passwort_reset", "sitzungen_beendet", "_key_art",
                    # only findable via a stem — composed, not a word of the list:
                    "KENNUNGSRAUM", "passwortregel", "sitzungsdauer", "Verzeichnisname"):
        assert german_in(german), f"{german!r} is not noticed by the name check"
    for english in ("federation_bind_existing", "federation_unbind", "SECURITY_EVENTS",
                     "count_other_sessions", "locked_series", "series", "start", "partial",
                     "binding", "TinySesam", "base", "base_url", "new_username", "mapping", "apply",
                     "source", "now", "methods", "message", "owner_id", "field", "path",
                     "browser_path", "after_response", "on_overflow", "artifact", "nachos",
                     "prefix", "background", "validate", "PAGES",
                     # the keys and values since 0.22.0 — and English words close to the list:
                     "applied", "bound", "conflict", "ambiguous", "not_in_directory",
                     "no_identifier", "refused", "local_password", "local", "directory",
                     "bound_to", "matches", "reason", "no_account", "service_account", "disabled",
                     "already_bound", "bound_elsewhere", "address_as_name", "invalid_identifier",
                     "self_chosen_name", "name_from_other_source", "binding_window_expired",
                     "failure_series", "dropped_roles", "remaining", "count",
                     "recovery_codes_deleted", "automation", "automatic", "human", "purpose",
                     "taken", "account_disabled", "admin_password_reset", "password_reset",
                     "sessions_revoked", "_key_kind", "old", "new", "alternative", "schema"):
        assert not german_in(english), f"{english!r}: false alarm ({german_in(english)})"

    # The probe is built from SOURCE TEXT: its German names are the test data, and the repository guard
    # (no German identifier in the code) must not see them as code.
    probe_source = """
class Probe:
    GUT = 1
    SICHERHEITSEREIGNISSE = ()

    def gut(self, request, *, by_operator=False):
        return None

    def schlecht(self, request, *, durch_betreiber=False):
        return None


class ProbeError(Exception):
    field = ""
    besitzer_id = None

    def __init__(self, nachricht: str, extra: str = ""):
        super().__init__(nachricht)
"""
    probe_package = type(sys)("probe_package")
    exec(probe_source, probe_package.__dict__)
    Probe, ProbeError = probe_package.Probe, probe_package.ProbeError
    storage = {"TinySesam": {"gut": {"tier": "A"}, "schlecht": {"tier": "B"}},
               "TinySesam.constants": {"GUT": {"tier": "A"}, "SICHERHEITSEREIGNISSE": {"tier": "C"}},
               "TinySesamConfig.fields": {"sperre_minuten": {"tier": "A"}, "ok_feld": {"tier": "C"}},
               "exports": {"ProbeError": {"tier": "A"}}}
    names = surface_names(storage, klass=Probe, package=probe_package)
    assert ("TinySesam.gut()", "by_operator") in names and ("ProbeError", "field") in names, names
    # Tier C does not count: The old names are there as aliases until 1.0.
    assert not any(n in ("SICHERHEITSEREIGNISSE", "ok_feld") for _, n in names), names
    # Through the same function as the normal run: the four German names, nothing else.
    findings, number = check_names(storage, klass=Probe, package=probe_package, required=(),
                                 at_least=(len(names), 0, 0))
    assert [b.split(": ")[1].split(" ")[0] for b in findings] == [
        "'durch_betreiber'", "'sperre_minuten'", "'besitzer_id'", "'nachricht'"], findings
    # … and the minimum count triggers when a kind is missing or too little is measured.
    findings, _ = check_names(storage, klass=Probe, package=probe_package,
                              required=(("ProbeError()", "message"),), at_least=(number + 1, 0, 0))
    assert len(findings) == 6 and "'message' is not measured" in findings[0] \
        and "too little measured" in findings[1], findings
    # Wired up: The normal run calls exactly this function — a check that would only
    # exist here would stay silent in the run.
    called = {k.func.id for k in ast.walk(ast.parse(inspect.getsource(main)))
               if isinstance(k, ast.Call) and isinstance(k.func, ast.Name)}
    assert "check_names" in called, "main() does not call check_names"
    ok("Name check triggers: German names, parameters, fields, attributes, constructor, "
       f"umlaut — {len(STEM)} stems, {len(GERMAN)} words, no false alarm on English ones")


# ---------- Keys and values of tiers A and B: English (0.22.0) ----------
# PO decision 2026-09-27 ("Translate everything, DB values too"): After the names also what the
# surface returns or accepts — the result dicts of the methods (`gc()`, the report of
# `federation_bind_existing`, `create_api_key` …), the payload of `on_security_event`, the context
# of custom pages (`set_template`: `ctx["prefix"]`, `ctx["purpose"]`), the JSON responses of the routes,
# the values of `kind` and what of it is in the database. No alias; stored values are carried over
# by the migration to schema 12 (`Store._values_english`), an old value is still read
# (tests/test_legacy_data.py). Audit and log lines stay as they are (fail2ban, operators'
# filters) — this check does not measure them.
#
# Measured twice: on the live object (a probe instance runs through the paths, a hook
# collects the events, custom templates record their context) and in the source (every
# call of `_security_event`, `render_page`, every key a built-in page reads from
# `ctx`, every returned JSON response of the routes). The probe sees what really
# goes out; the source what the probe does not reach (such as `passkey_added` without the extra).
# (Mutation probes: `failure_series` in `gc()` back to `fehlserien` → red; `reason=` in
# `_keys_revoked` back to `grund=` → red; `ctx.setdefault("prefix", …)` back to
# `"prefix"` → red; `create_api_key` writes `automaton` again → red; no longer calling the probe
# → wiring red.)

#: The keys and values up to 0.21.x — also those that passed as English as a word (`old` is an
#: English word and is therefore not in `GERMAN`). If one reappears, it is a
#: regression, not a new name.
OLD_VALUES = frozenset("""
    quelle ausgefuehrt gebunden konflikt mehrdeutig nicht_im_verzeichnis ohne_kennung abgewiesen
    lokal verzeichnis kennung grund gebunden_an treffer kein_konto dienstkonto gesperrt
    schon_gebunden anders_gebunden adresse_als_name kennung_ungueltig name_selbst_gewaehlt
    name_aus_quelle frist fehlserien verworfene_rollen alt neu anzahl verbleibend
    recovery_codes_geloescht automat mensch praefix zweck vergeben sperre admin_passwort
    passwort_reset sitzungen_beendet _key_art
""".split())


def value_findings(pairs: list) -> list:
    """Every key or value with a German word or from `OLD_VALUES`, as a readable line."""
    return [f"{where}: {value!r} ({', '.join(sorted(german_in(value)) or ['Name bis 0.21.x'])})"
            for where, value in pairs if german_in(value) or value in OLD_VALUES]


def _key_name(where: str, obj) -> list:
    """[(where, key)] of a dict, recursive for lists and sub-dicts."""
    pairs = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            pairs.append((where, str(k)))
            pairs += _key_name(f"{where}.{k}", v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            pairs += _key_name(f"{where}[]", v)
    return pairs


def values_of_probe(klass=TinySesam) -> list:
    """[(where, key_or_value)] — what a probe instance emits, on all paths that work without
    extra. `klass` for the self-probe (a subclass that delivers an old key)."""
    import re as _re
    import tempfile
    import pyotp
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    pairs: list = []
    with tempfile.TemporaryDirectory() as dirname:
        post: list = []
        events: list = []
        a = klass(TinySesamConfig(
            db_path=os.path.join(dirname, "probe.db"), cookie_secure=False, csrf_enabled=False,
            passkey_enabled=False, pin_enabled=True, magiclink_enabled=True,
            base_url="https://app.example.com"))
        a.set_mailer(lambda to, subject, text, html=None: post.append(text))
        a.on_security_event = lambda e, account, details: events.append((e, account, details))

        def link(path):
            return next(m.group(1) for t in reversed(post)
                        for m in [_re.search(rf"{path}([A-Za-z0-9_\-]+)", t)] if m)

        uid = a.create_user("probe", password="Probe-Pw-1234", email="probe@example.com")
        pairs += [("get_user()", k) for k in a.get_user(uid)]
        pairs += [("find_user()", k) for k in a.find_user("probe")]
        pairs += [("identifier_taken()", k) for k in a.identifier_taken("probe")]
        a.set_password(uid, "Neu-Pw-5678xyz")
        a.set_pin(uid, "4711")
        a.disable_pin(uid)
        tb = a.totp_begin(uid)
        pairs += _key_name("totp_begin()", tb)
        a.totp_confirm(uid, pyotp.TOTP(tb["secret"]).now())
        codes = a.generate_recovery_codes(uid)
        a._verify_recovery_code(uid, codes[0])
        a.totp_disable(uid)
        k = a.create_api_key(uid, name="probe")
        pairs += _key_name("create_api_key()", k) + [("create_api_key().kind", k["kind"])]
        km = a.create_api_key(uid, name="cli", kind="human")
        pairs += [("create_api_key(kind=).kind", km["kind"])]
        for e in a.list_api_keys(uid):
            pairs += _key_name("list_api_keys()[]", e) + [("list_api_keys()[].kind", e["kind"])]
        pairs += [("api_key_kind()", a.api_key_kind(km["key"])), ("api_key_kind()", a.api_key_kind(k["key"]))]
        account, _ = a.verify_api_key(k["key"])
        pairs += _key_name("verify_api_key()[0]", account)
        pairs += [("api_key.kind (Datenbank)", z["kind"])
                  for z in a.store._all("SELECT kind FROM api_key")]
        pairs += [("TinySesam._KEY_KINDS", w) for w in a._KEY_KINDS]
        a.revoke_api_key(k["id"])
        a.change_username(uid, "probe2")
        a.request_email_change(uid, "neu@example.com", "https://app.example.com")()
        tok = link("/auth/email/")
        pairs += _key_name("peek_magic(email_change)", a.peek_magic(tok))
        pairs += [("magic_token.payload (Datenbank)", k2) for z in
                  a.store._all("SELECT payload FROM magic_token WHERE purpose='email_change'")
                  for k2 in json.loads(z["payload"] or "{}")]
        pairs += [("confirm_email_change()", a.confirm_email_change(tok))]
        a.request_email_change(uid, "frei@example.com", "https://app.example.com")()
        tok = link("/auth/email/")
        a.create_user("dritte", email="frei@example.com")
        pairs += [("confirm_email_change()", a.confirm_email_change(tok))]
        inv = a.create_invite("gast@example.com", "https://app.example.com", roles=["leser"])
        pairs += _key_name("create_invite()", inv) + _key_name("peek_magic(invite)",
                                                                   a.peek_magic(inv["token"]))
        pairs += _key_name("own_events()", a.own_events(uid))
        pairs += _key_name("all_security()", a.all_security())

        # Custom pages: Which keys does a custom template really get?
        contexts: dict = {}

        def record(name):
            def fn(auth, ctx):
                contexts[name] = sorted(ctx)
                return "<p>probe</p>"
            return fn
        for page_html in ("login", "magic_confirm"):
            a.set_template(page_html, record(page_html))
        app = FastAPI()
        app.include_router(a.router())
        c = TestClient(app)
        c.get("/auth/login")
        c.get(f"/auth/magic/{a.create_magic_token('login', user_id=uid, email='neu@example.com')}")
        for page_html, key_name in contexts.items():
            pairs += [(f"set_template({page_html!r}) ctx", s) for s in key_name]

        # JSON of the routes, on the live object: account page and admin API.
        app.include_router(a.admin_router(), prefix="/probe-admin")
        a.create_user("chef", password="Chef-Pw-12345", is_admin=True)
        for name, pw in (("probe2", "Neu-Pw-5678xyz"), ("chef", "Chef-Pw-12345")):
            k_c = TestClient(app)
            k_c.post("/auth/login", data={"username": name, "password": pw}, follow_redirects=False)
            if name == "probe2":
                pairs += _key_name("GET /auth/me", k_c.get("/auth/me").json())
                new_k = k_c.post("/auth/apikeys", json={"name": "json"}).json()
                pairs += _key_name("POST /auth/apikeys", new_k)
                items = k_c.get("/auth/apikeys").json()
                pairs += _key_name("GET /auth/apikeys", items)
                pairs += [("GET /auth/apikeys[].kind", e.get("kind")) for e in items]
            else:
                accounts = k_c.get("/probe-admin/api/users").json()
                pairs += _key_name("GET <admin>/api/users", accounts)
        try:
            a.create_user("probe2")
        except ConfigError as e:
            pairs.append(("ConfigError.field", e.field))
        try:
            a.create_user("vierte", email="neu@example.com")
        except ConfigError as e:
            pairs.append(("ConfigError.field", e.field))

        # Events: the reason of the collective revocation is a value.
        a.set_disabled(uid, True)
        a.store.set_disabled(a.find_user("dritte")["id"], True)     # lock of an open confirmation
        boss_c = TestClient(app)
        boss_c.post("/auth/login", data={"username": "chef", "password": "Chef-Pw-12345"},
                    follow_redirects=False)
        pairs += [("GET <admin>/api/users[].disabled_by", k2["disabled_by"])
                  for k2 in boss_c.get("/probe-admin/api/users").json() if k2["disabled_by"]]
        for e, account_e, details in events:
            pairs += [(f"on_security_event({e!r}) konto", s) for s in account_e]
            pairs += _key_name(f"on_security_event({e!r}) details", details)
            if "reason" in details:
                pairs.append((f"on_security_event({e!r}).reason", details["reason"]))
        pairs += [("TinySesam._KEYS_REVOKED_REASONS", g) for g in a._KEYS_REVOKED_REASONS]

        # Existing-binding: all parts of the report, entries and reasons.
        class Directory:
            def entry_search(self, name):
                return {"anna": [{"id": "u-anna", "name": "Anna", "email": "anna@example.com"}],
                        "dora": [{"id": "u-d1"}, {"id": "u-d2"}],
                        "emil": [{"id": "u-fritz"}]}.get(name, [])
        a.ldap = Directory()
        for n in ("anna", "dora", "bert", "emil", "fritz"):
            a.create_user(n)
        a.store.link_federated("ldap", "u-fritz", a.find_user("fritz")["id"], 0)
        a.create_service("dienst")
        for report in (a.federation_bind_existing("ldap"),
                        a.federation_bind_existing("saml", mapping={"niemand": "x", "anna": "",
                                                                    "dienst": "d", "probe2": "p"})):
            pairs += _key_name("federation_bind_existing()", report)
            pairs += [("federation_bind_existing()[].reason", e["reason"])
                      for part in report.values() if isinstance(part, list)
                      for e in part if "reason" in e]
        pairs += [("NAME_BINDING_REFUSALS", g) for g in a.NAME_BINDING_REFUSALS]
        pairs += _key_name("gc()", a.gc())
    return pairs


def values_of_constants(file: dict) -> list:
    """[(where, value)] — the values of the constants of tiers A/B (elements, keys; running text with
    spaces not) and the defaults of the configuration fields that look like an abbreviation."""
    pairs = []
    for name, e in (file.get("TinySesam.constants") or {}).items():
        if not isinstance(e, dict) or e.get("tier") not in ("A", "B"):
            continue
        value = inspect.getattr_static(TinySesam, name, None)
        for w in (value if isinstance(value, (tuple, list, dict, frozenset, set)) else [value]):
            if isinstance(w, str) and " " not in w:
                pairs.append((f"TinySesam.{name}", w))
    for type_name in RESULT_TYPES.values():
        pairs += [(f"{type_name.__name__}.REASONS", w) for w in type_name.REASONS]
    for f in dataclasses.fields(TinySesamConfig):
        if isinstance(f.default, str) and re.fullmatch(r"[A-Za-z_]+", f.default or "-"):
            pairs.append((f"TinySesamConfig.{f.name} (Vorgabe)", f.default))
    return pairs


#: Modules with routes: What is returned there is a JSON response.
ROUTES_MODULE = ("router.py", "admin.py", "webauthn_.py", "oidc.py", "saml_.py", "gateway.py")


def values_in_code(sources: dict) -> list:
    """[(where, name)] from the source (`{filename: text}`): keyword arguments of every call of
    `_security_event` (the payload of `on_security_event`) and `render_page` (the context
    of custom pages), every key a built-in renderer reads from `ctx` or
    `render_page` puts into it, the keys of the `…_ctx` helpers, and every key of a
    returned JSON response in a routes module."""
    pairs = []

    def const(k):
        return k.value if isinstance(k, ast.Constant) and isinstance(k.value, str) else None

    def dict_key_name(node):
        if isinstance(node, ast.Dict):
            return [const(k) for k in node.keys if const(k)]
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "dict":
            return [k.arg for k in node.keywords if k.arg]
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            return dict_key_name(node.elt)
        if isinstance(node, ast.List):
            return [s for e in node.elts for s in dict_key_name(e)]
        return []

    for file, text in sorted(sources.items()):
        tree = ast.parse(text)
        for k in ast.walk(tree):
            if isinstance(k, ast.Call):
                name = k.func.attr if isinstance(k.func, ast.Attribute) else getattr(k.func, "id", "")
                if name == "_security_event":
                    pairs += [(f"{file}: on_security_event-Nutzlast", w.arg) for w in k.keywords if w.arg]
                elif name == "render_page":
                    pairs += [(f"{file}: render_page-Kontext", w.arg) for w in k.keywords
                              if w.arg and w.arg not in ("request", "status")]
                elif name in ("get", "setdefault") and isinstance(k.func, ast.Attribute) \
                        and getattr(k.func.value, "id", "") == "ctx" and k.args and const(k.args[0]):
                    pairs.append((f"{file}: ctx", const(k.args[0])))
                elif name == "JSONResponse" and file in ROUTES_MODULE and k.args:
                    pairs += [(f"{file}: JSON-Antwort", s) for s in dict_key_name(k.args[0])]
            elif isinstance(k, ast.Subscript) and getattr(k.value, "id", "") == "ctx" \
                    and const(k.slice):
                pairs.append((f"{file}: ctx", const(k.slice)))
            elif isinstance(k, ast.FunctionDef) and k.name.endswith("_ctx"):
                pairs += [(f"{file}: {k.name}", s) for r in ast.walk(k) if isinstance(r, ast.Return)
                          and r.value is not None for s in dict_key_name(r.value)]
            elif isinstance(k, ast.Return) and k.value is not None and file in ROUTES_MODULE:
                pairs += [(f"{file}: JSON-Antwort", s) for s in dict_key_name(k.value)]
    return pairs


def _sources(root: str = ROOT) -> dict:
    package = os.path.join(root, "tinysesam")
    sources = {}
    for n in sorted(os.listdir(package)):
        if n.endswith(".py"):
            with open(os.path.join(package, n), encoding="utf-8") as fh:
                sources[n] = fh.read()
    return sources


#: What the value check must see at minimum — one entry per path that occurs only there.
VALUES_REQUIRED = (("gc()", "failure_series"), ("create_api_key()", "dropped_roles"),
                 ("create_api_key(kind=).kind", "human"), ("list_api_keys()[].kind", "automation"),
                 ("api_key.kind (Datenbank)", "human"), ("magic_token.payload (Datenbank)", "old"),
                 ("peek_magic(email_change).payload", "old"), ("confirm_email_change()", "taken"),
                 ("federation_bind_existing()", "local_password"),
                 ("federation_bind_existing().conflict[]", "bound_to"),
                 ("federation_bind_existing().ambiguous[]", "matches"),
                 ("federation_bind_existing()[].reason", "no_account"),
                 ("on_security_event('api_keys_revoked').reason", "account_disabled"),
                 ("on_security_event('username_changed') details", "old"),
                 ("set_template('magic_confirm') ctx", "purpose"),
                 ("set_template('login') ctx", "prefix"),
                 ("webauthn_.py: on_security_event-Nutzlast", "name"),
                 ("manager.py: ctx", "prefix"), ("router.py: render_page-Kontext", "purpose"),
                 ("admin.py: JSON-Antwort", "disabled_by"), ("TinySesam.SECURITY_EVENTS", "api_keys_revoked"),
                 ("POST /auth/apikeys", "dropped_roles"), ("GET /auth/apikeys[].kind", "automation"),
                 ("GET <admin>/api/users[].disabled_by", "operator"),
                 ("GET <admin>/api/users[].disabled_by", "confirmation"), ("ConfigError.field", "email"))


def check_values(file: dict, klass=TinySesam, sources: "dict | None" = None,
                 required=VALUES_REQUIRED, at_least: int = 600) -> tuple:
    """(findings, count) — the whole value check of the normal run, with minimum count (as of 0.22.0:
    790 entries, with headroom downwards). The same function checks the self-probe."""
    pairs = (values_of_probe(klass) + values_of_constants(file)
             + values_in_code(_sources() if sources is None else sources))
    seen = set(pairs)
    missing = [f"{where}: {value!r} is not measured — probe or measurement broken?"
             for where, value in required if (where, value) not in seen]
    if len(pairs) < at_least:
        missing.append(f"too little measured: {len(pairs)} keys and values (expected at least "
                     f"{at_least})")
    return missing + value_findings(sorted(seen)), len(pairs)


def self_check_values() -> None:
    """Does the value check find an old key — in the probe and in the source?"""
    assert all(value_findings([("x", w)]) for w in OLD_VALUES), "OLD_VALUES measures nothing"
    assert not value_findings([("x", w)
                             for w in ("old", "new", "count", "reason", "human", "automation",
                                       "prefix", "purpose", "taken", "failure_series")]), \
        "False alarm on the English values"

    class Fallback(TinySesam):
        def gc(self, attempts_older_than_sec: int = 86400) -> dict:
            return {"fehlserien": 0, **super().gc(attempts_older_than_sec)}

    probe = [w for where, w in values_of_probe(Fallback) if where == "gc()"]
    assert "fehlserien" in probe and value_findings([("gc()", "fehlserien")]), probe
    source = {"router.py": 'def f(auth, request):\n'
                           '    auth._security_event("x", 1, anzahl=2)\n'
                           '    return auth.render_page("p", request=request, zweck="login")\n'
                           'def g():\n    return {"ok": True, "gebunden": []}\n'
                           'def _reg_ctx(nxt):\n    return dict(next=nxt, kennung="")\n',
              "templates.py": 'def _p(auth, ctx):\n    return ctx.get("praefix") + ctx["alt"]\n'}
    hits = sorted({w for _, w in values_in_code(source) if value_findings([("", w)])})
    assert hits == ["alt", "anzahl", "gebunden", "kennung", "praefix", "zweck"], hits
    findings, _ = check_values({}, sources={}, required=(("gc()", "does-not-exist"),),
                              at_least=10 ** 6)
    assert "'does-not-exist' is not measured" in findings[0] and "too little measured" in findings[1], \
        findings[:2]
    called = {k.func.id for k in ast.walk(ast.parse(inspect.getsource(main)))
               if isinstance(k, ast.Call) and isinstance(k.func, ast.Name)}
    assert "check_values" in called, "main() does not call check_values"
    ok("Value check triggers: an old key in the probe (gc), in an event, in the context "
       "of a page, in a JSON response, in a ctx helper; minimum count and wiring")


# ---------- The operator and proxy contract (PO decision 2026-10-29) ----------
# Besides the Python names the promise covers: `auth.cfg` and `auth.on_security_event` (tier A), the forward/gate
# contract that proxies use (tier A) and the HTML pages (tier B, path and method), the logger names and the
# security-log lines that fail2ban filters read (tier A). The MEASUREMENT is in `tests/_contract.py` and
# `tests/_contract_probe.py`; the tiers are decisions in `tests/api_surface.json`. What follows holds the
# decision against that file: nothing that the decision puts in A may sit lower, the scan must see what FastAPI
# sees, and the measurement must not shrink without anyone noticing.

#: The areas of the contract measurement.
CONTRACT_AREAS = ("TinySesam.attributes", "TinySesam.event_payload", "http.routes", "http.forward",
                    "http.contract", "log.loggers", "log.lines")
#: Entries of these areas are tier A in whole (the decision names them as a block).
CONTRACT_AREAS_A = ("TinySesam.attributes", "TinySesam.event_payload", "http.forward", "log.loggers", "log.lines")
#: In `http.contract` everything is tier A except these — hints to the account page's script, not to proxies.
CONTRACT_CONTRACT_NOT_A = ("header:X-TinySesam-Factor", "header:X-TinySesam-Reauth")
#: Request headers a BROWSER sends (PO decision 2026-10-29, "last breaking pass"): not an operator contract, because
#: no proxy has to set or pass them on specially. They sit in tier B, and the guard refuses A for them. Tier A in
#: `request-header:*` is what a proxy sets or passes on: `Host`, `Authorization`, `X-Api-Key`, `X-Forwarded-*`,
#: `X-Original-Uri|Url`, `X-TinySesam-Roles` (the `Cookie` header and its names are described in OPERATIONS.md).
CONTRACT_BROWSER_HEADER = ("request-header:Accept", "request-header:Referer", "request-header:Sec-Fetch-Mode",
                          "request-header:Sec-Fetch-Site", "request-header:X-Csrf-Token")
#: The paths of the forward/gate contract, tier A at least; every other route may be B (path and method).
GATE_PATHS = ("/auth/forward", "/auth/verify")
GATE_PREFIXES = ("/.tinysesam/", "/auth/gate/")
#: Paths that other systems have registered by hand or poll — the identity provider (OIDC callback, SAML ACS and
#: metadata) and the container health check: tier A at least (PO decision 2026-10-29). Moving one costs an operator a
#: reconfiguration at the provider. `<oidc_callback_path>` is the configured path (`TinySesamConfig.oidc_callback_path`).
IDP_PATHS = ("<oidc_callback_path>", "/auth/saml/acs", "/auth/saml/metadata", "/healthz")

#: What the contract measurement must see at minimum — otherwise it silently measures less than it promises.
CONTRACT_REQUIRED = (
    ("http.routes", "GET /auth/forward"), ("http.routes", "GET /auth/verify"),
    ("http.routes", "GET /.tinysesam/start"), ("http.routes", "GET /.tinysesam/callback"),
    ("http.routes", "POST /.tinysesam/logout"), ("http.routes", "GET /auth/gate/authorize"),
    ("http.routes", "POST /auth/login"), ("http.routes", "GET <admin>/api/users"),
    ("http.forward", "forward: role missing (?roles=)"), ("http.forward", "gateway callback: valid code"),
    ("http.contract", "header:X-TinySesam-Reason"), ("http.contract", "header:X-TinySesam-Location"),
    ("http.contract", "header:X-TinySesam-Gate-Cookie"), ("http.contract", "reason:role"),
    ("http.contract", "reason:app-signed-out"), ("http.contract", "request-header:X-Forwarded-Uri"),
    ("http.contract", "request-header:X-Forwarded-Host"), ("http.contract", "request-param:roles"),
    ("http.contract", "cookie:__Host-tinysesam_link"),
    ("log.loggers", "tinysesam.security"), ("log.loggers", "tinysesam"),
    ("log.lines", "event:failed login"), ("log.lines", "event:failed verification"),
    ("log.lines", "event:deferred login"), ("log.lines", "line:WARNING failed login | user ip method reason"),
    ("log.lines", "format:%(asctime)s %(levelname)s %(message)s"), ("log.lines", "value:unban=yes"),
    ("TinySesam.attributes", "cfg"), ("TinySesam.attributes", "on_security_event"),
    ("TinySesam.event_payload", "username_changed"), ("TinySesam.event_payload", "api_keys_revoked"))
CONTRACT_AT_LEAST = {"http.routes": 80, "http.forward": 20, "http.contract": 20, "log.lines": 20,
                      "TinySesam.event_payload": 14, "log.loggers": 3}


def contract_lower_limit(area: str, name: str) -> "str | None":
    """The lowest tier the decision of 2026-10-29 allows this entry: "A", or None where A or B is free."""
    if area in CONTRACT_AREAS_A:
        return "A"
    if area == "http.contract":
        return None if name in CONTRACT_CONTRACT_NOT_A or name in CONTRACT_BROWSER_HEADER else "A"
    if area == "http.routes":
        path = name.split(" ", 1)[1]
        return "A" if path in GATE_PATHS + IDP_PATHS or path.startswith(GATE_PREFIXES) else None
    return None


def contract_findings(file: dict, now: dict, live_routes: "dict | None" = None,
                    required=CONTRACT_REQUIRED, at_least=CONTRACT_AT_LEAST) -> list:
    """The whole contract check of the normal run — the same function checks the self-probe."""
    findings = []
    for area in CONTRACT_AREAS:
        for name, e in sorted((file.get(area) or {}).items()):
            should = contract_lower_limit(area, name)
            tier = e.get("tier") if isinstance(e, dict) else None
            if should == "A" and tier is not None and tier != "A":
                findings.append(f"{area}.{name}: tier {tier}, but the decision of 2026-10-29 puts it in A")
    for name in CONTRACT_BROWSER_HEADER:
        e = (file.get("http.contract") or {}).get(name)
        if isinstance(e, dict) and e.get("tier") == "A":
            findings.append(f"http.contract.{name}: tier A, but a header the browser sends is no operator contract "
                           "(decision of 2026-10-29, last breaking pass): tier B")
    for area, name in required:
        measured = now.get(area, {})
        if name not in measured:
            findings.append(f"{area}: {name!r} is not measured — measurement broken or the contract changed?")
    for area, number in at_least.items():
        if len(now.get(area, {})) < number:
            findings.append(f"{area}: only {len(now.get(area, {}))} entries measured (expected at "
                           f"least {number}) — measurement broken?")
    # Cross-checks against things the surface already pins by itself.
    if set(now["TinySesam.event_payload"]) != set(TinySesam.SECURITY_EVENTS):
        findings.append("TinySesam.event_payload: events with a payload "
                       f"{sorted(set(now['TinySesam.event_payload']) ^ set(TinySesam.SECURITY_EVENTS))} "
                       "differ from TinySesam.SECURITY_EVENTS")
    if security.seclog.name not in now["log.loggers"]:
        findings.append(f"log.loggers: the security logger is called {security.seclog.name!r}, "
                       "which the source scan does not list")
    signed_in = now["http.forward"].get("forward: signed in", "")
    for h in TinySesam.FORWARD_HEADERS_DEFAULT.values():
        if CT.canonical_header(h) not in signed_in:
            findings.append(f"http.forward: 'forward: signed in' does not carry {h} although "
                           "TinySesam.FORWARD_HEADERS_DEFAULT names it")
    for w in sorted(CT.filter_words()):
        if f"event:{w}" not in now["log.lines"]:
            findings.append(f"log.lines: the shipped fail2ban filters name the event word {w!r}, "
                           "but no log call produces it any more")
    if live_routes is not None:
        findings += [f"http.routes: {z}" for z in CT.routes_differences(now["http.routes"], live_routes)]
    return findings


def self_check_contract(now: dict) -> None:
    """Does the contract measurement react — on mutated copies of the source, not on the real tree?

    Each case bends ONE place and demands that the matching entry disappears (or changes), and that the
    comparison reports it as a break with the tier of the entry. The real mutation runs (the package itself
    changed, the suite run) are in the CHANGELOG; this keeps the measurement honest between them."""
    sources = CT.read_sources()

    def bent(file, old, new, count=1):
        assert sources[file].count(old) >= 1, f"{file}: mutation anchor {old!r} not found"
        copy = dict(sources)
        copy[file] = sources[file].replace(old, new, count)
        return copy

    def check(area, measure, copy, away, add=None):
        before, afterwards = measure(sources), measure(copy)
        assert away in before and away not in afterwards, (area, away, "is still there after the mutation")
        if add is not None:
            assert add in afterwards, (area, add)
        s = {area: {away: "A"}}
        b, _ = assess({area: before}, {area: afterwards}, s)
        assert any(away in z and z.startswith("[A]") for z in b), (area, away, b)

    routes = CT.routes_static
    check("http.routes", routes, bent("router.py", '@r.get("/auth/forward")', '@r.get("/auth/forwards")'),
           "GET /auth/forward", "GET /auth/forwards")
    check("http.routes", routes, bent("router.py", '@r.post("/.tinysesam/logout")', '@r.get("/.tinysesam/logout2")'),
           "POST /.tinysesam/logout", "GET /.tinysesam/logout2")
    # a dropped parameter is a break (list value), a gained one an extension
    before = routes(sources)["GET /.tinysesam/start"]
    copy = bent("router.py", "def gate_link_start(request: Request, rd: str = \"/\", signed_out: str = \"\"):",
                     "def gate_link_start(request: Request, rd: str = \"/\"):")
    b, e = assess({"http.routes": {"GET /.tinysesam/start": before}},
                     {"http.routes": {"GET /.tinysesam/start": routes(copy)["GET /.tinysesam/start"]}},
                     {"http.routes": {"GET /.tinysesam/start": "A"}})
    assert b and b[0].startswith("[A]") and "query:signed_out" in b[0] and not e, (b, e)
    b, e = assess({"http.routes": {"GET /.tinysesam/start": routes(copy)["GET /.tinysesam/start"]}},
                     {"http.routes": {"GET /.tinysesam/start": before}})
    assert not b and e and "query:signed_out" in e[0], (b, e)
    # a route the scan cannot see is refused, not ignored
    for foreign in ("app.add_api_route('/x', f)", "app.mount('/x', sub)"):
        try:
            routes(bent("gateway.py", "def build_app(", foreign + "\ndef build_app(", 1))
        except CT.MeasurementError:
            pass
        else:
            raise AssertionError(f"{foreign}: the route scan accepted a registration it cannot see")
    atoms = CT.contract_atoms
    check("http.contract", atoms, bent("router.py", 'headers={"X-TinySesam-Reason": "role"}',
                                            'headers={"X-TinySesam-Reason": "denied"}'),
           "reason:role", "reason:denied")
    check("http.contract", atoms, bent("router.py", '"X-TinySesam-Reason": "app-signed-out"',
                                            '"X-TinySesam-Reason": "app-out"'), "reason:app-signed-out")
    check("http.contract", atoms, bent("manager.py", '_GATE_LINK_COOKIE = "__Host-tinysesam_link"',
                                            '_GATE_LINK_COOKIE = "__Host-tinysesam_conn"'),
           "cookie:__Host-tinysesam_link", "cookie:__Host-tinysesam_conn")
    check("http.contract", atoms, bent("manager.py", 'h.get("x-forwarded-uri")', 'h.get("x-fwd-uri")'),
           "request-header:X-Forwarded-Uri", "request-header:X-Fwd-Uri")
    check("http.contract", atoms, bent("router.py", 'getlist("roles")', 'getlist("role")'),
           "request-param:roles", "request-param:role")
    check("http.contract", atoms, bent("router.py", 'head["X-TinySesam-Gate-Cookie"]', 'head["X-Gate-Cookie"]'),
           "header:X-TinySesam-Gate-Cookie")
    check("log.loggers", CT.loggers_static,
           bent("security.py", 'getLogger("tinysesam.security")', 'getLogger("tinysesam.sec")'),
           "tinysesam.security", "tinysesam.sec")
    # uvicorn's logger (B-5) is foreign, not a promised name; any other foreign name is refused, not ignored.
    assert "uvicorn.error" not in CT.loggers_static(sources), "a foreign logger counted as a promised name"
    for name in ("tinysesm.security", "uvicorn.access"):
        try:
            CT.loggers_static(bent("gateway.py", 'getLogger("uvicorn.error")', f'getLogger("{name}")'))
        except CT.MeasurementError:
            pass
        else:
            raise AssertionError(f"{name}: the logger scan let a name outside tinysesam* through")
    log = lambda q: CT.log_atoms(q, security.NOT_LOGIN_METHODS)           # noqa: E731
    # A shape produced by ONE call site: bending that site makes it disappear. (A shape several sites produce,
    # such as `failed login | user ip method reason`, survives bending one of them on purpose: merging or
    # moving call sites is no break of what a filter reads.)
    generic = 'security.seclog.warning("%s user=%s ip=%s method=%s", security.log_event(method),'
    check("log.lines", log, bent("manager.py", generic, generic.replace('ip=%s', 'client=%s')),
           "line:WARNING failed login | user ip method", "line:WARNING failed login | user client method")
    check("log.lines", log, bent("manager.py", generic, generic.replace(".warning(", ".error(")),
           "line:WARNING failed login | user ip method", "line:ERROR failed login | user ip method")
    check("log.lines", log, bent("manager.py", "ip=%s method=blocked reason=%s", "ip=%s method=refused reason=%s"),
           "value:method=blocked", "value:method=refused")
    check("log.lines", log, bent("manager.py", '"%s user=%s ip=%s method=%s unban=%s"',
                                      '"%s user=%s ip=%s method=%s lift=%s"'),
           "line:INFO login ok | user ip method unban")
    check("log.lines", log, bent("security.py", 'logging.Formatter("%(asctime)s %(levelname)s %(message)s")',
                                      'logging.Formatter("%(levelname)s %(message)s")'),
           "format:%(asctime)s %(levelname)s %(message)s", "format:%(levelname)s %(message)s")
    # An event word the shipped filters name that no call produces any more is a finding of its own.
    check("log.lines", log, bent("manager.py", '"deferred %s user=%s ip=%s reason=pending"',
                                      '"postponed %s user=%s ip=%s reason=pending"'), "event:deferred login")
    without_word = json.loads(json.dumps(now))
    without_word["log.lines"].remove("event:deferred login")
    assert any("'deferred login'" in z for z in contract_findings(tiers_full(now), without_word)), \
        "a vanished event word that a shipped filter names went unnoticed"
    # the payload of the hook: a renamed key is gone, a new key is only an extension
    prior = CT.event_payload(sources)
    after = CT.event_payload(bent("manager.py", '_security_event("username_changed", user_id, old=old, new=name)',
                                     '_security_event("username_changed", user_id, was=old, new=name)'))
    assert prior["username_changed"] == ["new", "old"] and after["username_changed"] == ["new", "was"], after
    b, e = assess({"TinySesam.event_payload": {"username_changed": prior["username_changed"]}},
                     {"TinySesam.event_payload": {"username_changed": after["username_changed"]}},
                     {"TinySesam.event_payload": {"username_changed": "A"}})
    assert b and b[0].startswith("[A]") and "old" in b[0] and e and "was" in e[0], (b, e)
    try:
        CT.event_payload(bent("manager.py", '_security_event("username_changed", user_id, old=old, new=name)',
                                  '_security_event(event_name, user_id, old=old, new=name)'))
    except CT.MeasurementError:
        pass
    else:
        raise AssertionError("an event name that is not a literal was accepted")
    # the tier floor: A decided, B entered -> reported; a promotion B -> A is free; C never
    file = json.loads(json.dumps(tiers_full(now)))
    assert contract_findings(file, now) == [], contract_findings(file, now)
    for area, name in (("http.routes", "GET /auth/forward"), ("http.routes", "GET /.tinysesam/start"),
                          ("http.routes", "GET /auth/gate/logout"), ("http.forward", "forward: not signed in"),
                          ("log.loggers", "tinysesam.security"), ("log.lines", "event:failed login"),
                          ("TinySesam.attributes", "cfg"), ("TinySesam.attributes", "on_security_event"),
                          ("TinySesam.event_payload", "pin_set"), ("http.contract", "reason:role"),
                          ("http.contract", "request-header:X-Forwarded-Uri")):
        lowered = json.loads(json.dumps(file))
        lowered[area][name]["tier"] = "B"
        assert any(f"{area}.{name}: tier B" in z for z in contract_findings(lowered, now)), (area, name)
    # the paths the identity provider and the health check use (decision of 2026-10-29): not below A
    for name in ("GET <oidc_callback_path>", "POST /auth/saml/acs", "GET /auth/saml/metadata", "GET /healthz"):
        assert name in file["http.routes"], f"{name}: the provider path is no longer measured (renamed or removed?)"
        lowered = json.loads(json.dumps(file))
        lowered["http.routes"][name]["tier"] = "B"
        assert any(f"http.routes.{name}: tier B" in z for z in contract_findings(lowered, now)), name
    # the headers a browser sends: not A (the narrowing of the same decision is held, too)
    for name in CONTRACT_BROWSER_HEADER:
        assert name in file["http.contract"], f"{name}: the browser header is no longer measured"
        raised = json.loads(json.dumps(file))
        assert raised["http.contract"][name]["tier"] == "B", name
        raised["http.contract"][name]["tier"] = "A"
        assert any(f"http.contract.{name}: tier A" in z for z in contract_findings(raised, now)), name
    assert all(file["http.contract"][n]["tier"] == "A" for n in now["http.contract"]
               if n.startswith("request-header:") and n not in CONTRACT_BROWSER_HEADER), \
        "a header a proxy sets or passes on must be tier A"
    free = json.loads(json.dumps(file))
    free["http.routes"]["GET /auth/login"]["tier"] = "B"             # an HTML page: B is the decision
    free["http.contract"]["header:X-TinySesam-Reauth"]["tier"] = "B"
    free["http.routes"]["POST /auth/pin"]["tier"] = "A"              # a promotion needs no excuse
    assert contract_findings(free, now) == [], contract_findings(free, now)
    # the measurement may not shrink silently
    small = json.loads(json.dumps(now))
    small["http.contract"].remove("reason:role")
    assert any("reason:role" in z for z in contract_findings(file, small)), "a lost mandatory entry went unnoticed"
    small = json.loads(json.dumps(now))
    small["http.routes"] = {k: v for k, v in list(small["http.routes"].items())[:10]}
    assert any("http.routes: only 10" in z for z in contract_findings(file, small)), "a shrunken scan went unnoticed"
    # the scan must see what FastAPI sees
    live = {"GET /auth/forward": [], "GET /invented": []}
    assert any("live route 'GET /invented'" in z for z in CT.routes_differences(now["http.routes"], live))
    live = {"GET /.tinysesam/start": ["query:rd"]}
    assert any("query:signed_out" in z for z in CT.routes_differences(now["http.routes"], live))
    called = {k.func.id for k in ast.walk(ast.parse(inspect.getsource(main)))
               if isinstance(k, ast.Call) and isinstance(k.func, ast.Name)}
    assert "contract_findings" in called, "main() does not call contract_findings"
    ok("Contract measurement triggers: a renamed route or parameter, a changed header/reason/cookie/input, a "
       "renamed logger, a changed log shape or file format, a renamed payload key; unseen routes refused; "
       "the tier floor holds; the measurement cannot shrink silently")


# ---------- What operators and proxies read: English too (PO decision 2026-10-29, "last breaking pass") ----------
# `check_names` covers the Python names, `check_values` the keys and values the Python surface returns. This
# check covers the rest of what the promise now names: query/form parameters of the routes, header and cookie
# names, logger names, event words and keys of the security log (and the values behind `reason=`, `method=` and
# `unban=`), the ids and placeholders of the message catalogue (`add_messages`), the names the deployment
# templates read from the environment, the options of the command line and the free text of the log lines.
# (Mutation probes: `signed_out` back to `abgemeldet` in a route → red; a German event word or key in the
# security log → red; a German message id → red; `TS_SHARE_PREFIX` back to `TS_SHARE_PRAEFIX` → red; a German
# log text in the mail queue → red; a German option → red.)

#: German words that stand in running log text. As a whole word, lower case; none of them is an English word.
LOG_GERMAN = frozenset("""
    hinweis warteschlange versand gescheitert betroffene betroffenen passendes erst einmal vergeben abgelehnt
    antwort verworfen auftrag abgewiesen ohne voll nicht wurde wird werden ist sind nur kein keine fuer wegen
    und oder mit von nach bei zur zum aus auf einer eines einem
""".split())


def german_in_text(text: str) -> set:
    """What is German in a running text (a log format string): whole words from `LOG_GERMAN`/`GERMAN` that
    are no English word, stems from `STEM`, umlauts. `%s`-style fields and punctuation do not count."""
    hits = {z for z in text if not z.isascii() and z not in "—–…→←“”„’•·×≥≤≠±°²"}
    for w in re.findall(r"[A-Za-zÄÖÜäöüß]+", text):
        w = w.lower()
        if w in LOG_GERMAN or (w in GERMAN and w not in ENGLISH_IN_TEXT) or any(s in w for s in STEM):
            hits.add(w)
    return hits


#: Entries of `GERMAN` that are also ordinary English words in running text (`art`, `base`); every other word
#: of `GERMAN` counts as German in a log text, and a false hit there is a finding about the list.
ENGLISH_IN_TEXT = frozenset({"art", "basis"})


def log_texts(sources: dict) -> list:
    """[(where, text)] — the literal format string of every log call (`<x>.debug|info|warning|error|critical|
    exception("...")`, also an f-string's literal parts) in the package."""
    pairs = []
    for file, text in sorted(sources.items()):
        for k in ast.walk(ast.parse(text)):
            if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                    and k.func.attr in ("debug", "info", "warning", "error", "critical", "exception") and k.args):
                continue
            a = k.args[0]
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                pairs.append((f"{file}:{k.lineno}", a.value))
            elif isinstance(a, ast.JoinedStr):
                pairs.append((f"{file}:{k.lineno}", " ".join(
                    v.value for v in a.values if isinstance(v, ast.Constant) and isinstance(v.value, str))))
    return pairs


def cli_options(source: str) -> list:
    """The option strings of the command line (`add_argument("--x", ...)`) and its sub-command names."""
    names = []
    for k in ast.walk(ast.parse(source)):
        if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr == "add_argument":
            names += [a.value for a in k.args if isinstance(a, ast.Constant) and isinstance(a.value, str)
                      and a.value.startswith("-")]
    return names


def deploy_environment_names(root: str = ROOT) -> list:
    """[(file, name)] — the `TS_*` variables the deployment templates read (`{$TS_X:default}`, comments)."""
    pairs = []
    folder = os.path.join(root, "deploy", "forward-auth")
    for file in sorted(os.listdir(folder)):
        path = os.path.join(folder, file)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            for n in sorted(set(re.findall(r"\bTS_[A-Z0-9_]+", fh.read()))):
                pairs.append((f"deploy/forward-auth/{file}", n))
    return pairs


def contract_names(file: dict, sources: dict, root: str = ROOT, messages=None) -> list:
    """[(where, name)] — every name the contract measurement carries that a person could read as German.
    The baseline (`file`) supplies the routes, headers, cookies, loggers and log atoms; the sources the rest."""
    from tinysesam import messages as _msg
    pairs = []
    for route, e in (file.get("http.routes") or {}).items():
        if e.get("tier") not in ("A", "B"):
            continue
        pairs += [(f"{route} parameter", p.split(":", 1)[1]) for p in e.get("keys", [])]
        pairs += [(f"{route} path segment", s) for s in re.split(r"[/{}<>]", route.split(" ", 1)[1]) if s]
    for atom in (file.get("http.contract") or {}):
        kind, _, rest = atom.partition(":")
        pairs.append((f"http.contract {kind}", rest.removeprefix("__Host-")))
    for atom in (file.get("log.loggers") or {}):
        pairs.append(("log.loggers", atom))
    for atom in (file.get("log.lines") or {}):
        kind, _, rest = atom.partition(":")
        if kind == "format":
            continue
        if kind == "line":
            pairs += [("log.lines keys", w) for w in rest.split("|", 1)[1].split()]
            pairs += [("log.lines event", rest.split("|", 1)[0].split(" ", 1)[1].strip())]
        elif kind == "value":
            pairs.append(("log.lines value", rest))
        else:
            pairs.append((f"log.lines {kind}", rest))
    for f in dataclasses.fields(TinySesamConfig):
        if "cookie" in f.name and isinstance(f.default, str):
            pairs.append((f"TinySesamConfig.{f.name} (default)", f.default))
    catalog = _msg.MESSAGES if messages is None else messages
    ids, placeholder = set(), set()
    for language, texts in catalog.items():
        ids |= set(texts)
        for t in texts.values():
            placeholder |= set(re.findall(r"\{(\w+)\}", t))
    pairs += [("messages id", i) for i in sorted(ids)] + [("messages placeholder", p) for p in sorted(placeholder)]
    if "__main__.py" in sources:
        pairs += [("command line option", o.lstrip("-")) for o in cli_options(sources["__main__.py"])]
    pairs += [(f"{d}", n) for d, n in deploy_environment_names(root)]
    return pairs


def _word_by_word(name: str) -> str:
    """Event words, `key=value` atoms and hyphenated header names split into words like an identifier."""
    return re.sub(r"[ \-=:|]", "_", name)


def contract_names_findings(pairs: list) -> list:
    return [f"{where}: {name!r} ({', '.join(sorted(german_in(_word_by_word(name))))})"
            for where, name in pairs if german_in(_word_by_word(name))]


#: What the measurement must see at minimum — otherwise it silently measures less than it promises.
CONTRACT_NAMES_REQUIRED = (("GET /.tinysesam/start parameter", "signed_out"), ("GET /auth/login parameter", "signed_out"),
                         ("http.contract reason", "app-signed-out"), ("http.contract cookie", "tinysesam_link"),
                         ("log.loggers", "tinysesam.security"), ("log.lines event", "failed login"),
                         ("log.lines keys", "unban"), ("log.lines value", "reason=account_locked"),
                         ("messages id", "login.logged_out"), ("messages placeholder", "reason"),
                         ("command line option", "db"), ("deploy/forward-auth/Caddyfile.gate", "TS_GATE_PUBKEY"))


def check_contract_names(file: dict, sources: "dict | None" = None, required=CONTRACT_NAMES_REQUIRED,
                         at_least: int = 300, root: str = ROOT) -> tuple:
    """(findings, count) — names of the contract in English, free text of the log lines included."""
    sources = _sources(root) if sources is None else sources
    pairs = contract_names(file, sources, root)
    seen = set(pairs)
    missing = [f"{where}: {name!r} is not measured — measurement broken?" for where, name in required
             if (where, name) not in seen]
    if len(pairs) < at_least:
        missing.append(f"too little measured: {len(pairs)} names (expected at least {at_least})")
    texts = log_texts(sources)
    if len(texts) < 90:
        missing.append(f"too little measured: {len(texts)} log texts (expected at least 90)")
    findings = contract_names_findings(sorted(seen))
    findings += [f"log text {where}: {t[:70]!r} ({', '.join(sorted(german_in_text(t)))})"
                for where, t in texts if german_in_text(t)]
    return missing + findings, len(pairs) + len(texts)


def self_check_contract_names() -> None:
    """Does the check find a German route parameter, header, event word, key, message id, environment variable,
    option and log text — and nothing in the English ones?"""
    base = {"http.routes": {"GET /x": {"keys": ["query:abgemeldet"], "tier": "B"}},
             "http.contract": {"cookie:__Host-tinysesam_verbindung": {"tier": "A"},
                               "header:X-TinySesam-Grund": {"tier": "A"}},
             "log.loggers": {"tinysesam.sicherheit": {"tier": "A"}},
             "log.lines": {"line:WARNING anmeldung gescheitert | konto ip": {"tier": "A"},
                           "value:reason=konto_gesperrt": {"tier": "A"}}}
    found = " ".join(contract_names_findings(contract_names(base, {}, messages={
        "en": {"err.locked_serie": "x {grund}"}})))
    for word in ("abgemeldet", "verbindung", "grund", "sicherheit", "gescheitert", "konto", "serie"):
        assert word in found, (word, found)
    assert not contract_names_findings([("x", w) for w in (
        "signed_out", "tinysesam_link", "reason", "failed login", "account_locked", "locked_series", "yes", "db",
        "TS_SHARE_PREFIX", "app-signed-out")]), "false alarm on the English names"
    assert cli_options('ap.add_argument("--ja")\nap.add_argument("db")\nap.add_argument("-n", "--yes")') \
        == ["--ja", "-n", "--yes"]
    assert any("Warteschlange" in t or "warteschlange" in german_in_text(t) for t in
               ["Mail-Warteschlange voll (%d) — Versand verworfen"]) and \
        german_in_text("Mail-Warteschlange voll (%d) — Versand verworfen") == {"warteschlange", "voll", "versand", "verworfen"}
    assert not german_in_text("Sign-in for user=%s locked: %d failed attempts in a row. Lift: %s.")
    hits = log_texts({"m.py": 'log.warning("Hinweis voll")\nlog.error(f"Auftrag {x} gescheitert")\nlog.info(x)\n'})
    assert [" ".join(t.split()) for _, t in hits] == ["Hinweis voll", "Auftrag gescheitert"], hits
    findings, _ = check_contract_names({}, sources={}, required=(("log.loggers", "none"),), at_least=10 ** 6)
    assert "'none' is not measured" in findings[0] and "too little measured" in findings[1], findings[:2]
    called = {k.func.id for k in ast.walk(ast.parse(inspect.getsource(main)))
               if isinstance(k, ast.Call) and isinstance(k.func, ast.Name)}
    assert "check_contract_names" in called, "main() does not call check_contract_names"
    ok("Contract-name check triggers: route parameter, header, cookie, logger, event word, key, value, message id, "
       "placeholder, environment variable, option, log text; minimum count and wiring")


def tiers_full(now: dict) -> dict:
    """A synthetic baseline for the self-check: every entry tiered as the decision of 2026-10-29 puts it."""
    file = with_tiers(now, {})
    for area in CONTRACT_AREAS:
        for name, e in file[area].items():
            e["tier"] = contract_lower_limit(area, name) or "B"
    return file


def _count_tiers(file: dict) -> str:
    number = {s: 0 for s in TIERS}
    for per_name in tiers_from(file).values():
        for tier in per_name.values():
            number[tier] = number.get(tier, 0) + 1
    return ", ".join(f"{s} {n}" for s, n in number.items())


def _report_without_tier(missing: list) -> None:
    print(f"\n  {len(missing)} public names without a valid tier:\n")
    for line in missing:
        print(f"    NO TIER     {line}")
    print("\n  Every public name needs an explicit tier — in tests/api_surface.json")
    print('  set `"tier": "A"|"B"|"C"` on the entry (meaning: API.md, „Drei Stufen“):')
    for tier, text in TIERS.items():
        print(f"    {tier}  {text}")
    print("  Nothing public should arise by accident: If the name is internal, it gets a")
    print("  leading underscore and disappears from the baseline.\n")


def main(argv):
    now = surface()
    self_check(now)
    self_check_signature(now)
    self_check_tiers(now)
    self_check_c()
    self_check_names()
    self_check_values()
    self_check_contract_names()
    self_check_contract(now)

    earlier_file = {}
    if os.path.exists(STORAGE):
        with open(STORAGE, encoding="utf-8") as fh:
            earlier_file = json.load(fh)

    if "--update" in argv:
        storage = with_tiers(now, earlier_file)
        with open(STORAGE, "w", encoding="utf-8") as fh:
            json.dump(storage, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
        print(f"  Surface pinned: {STORAGE}")
        missing = without_tier(storage)
        if missing:
            _report_without_tier(missing)
            return 1
        return 0

    if not earlier_file:
        print(f"  {STORAGE} is missing — create it once with: python tests/test_api_surface.py --update")
        return 1

    red, missing, breaks, extensions = compare(earlier_file, now)
    if missing:
        _report_without_tier(missing)
    else:
        ok(f"every public name has a tier ({_count_tiers(earlier_file)})")

    # Tier C (0.22.0): aliases, no calls of old names in own code, deadline 1.0.
    c_error, c_files = c_findings(earlier_file)
    assert c_files >= 20, f"only {c_files} files searched for old names — path broken?"
    if c_error:
        red = True
        print(f"\n  {len(c_error)} findings on tier C (alias until 1.0):\n")
        for line in c_error:
            print(f"    TIER C       {line}")
        print("\n  Tier C means: The implementation carries an underscore, the old name is "
              "`Deprecated(\"_name\", \"<Ersatz>\")`\n  (tinysesam/_deprecated.py), and nothing in the "
              "package calls it. The entry in tests/api_surface.json\n  carries `target`, `since` and "
              "`until`.\n")
    else:
        ok(f"Tier C: {len(c_entries(earlier_file))} aliases warn exactly once and point to "
           f"their implementation, an assignment on the object (test fake) warns; {c_files} "
           "files without an old name")
    check_subclass()
    check_warning_filter()

    # The names of tiers A and B are English (PO decision 2026-09-27).
    n_error, n_number = check_names(earlier_file)
    if n_error:
        red = True
        print(f"\n  {len(n_error)} names of tiers A/B with a German word (or measurement too small):\n")
        for line in n_error:
            print(f"    GERMAN       {line}")
        print("\n  The public surface is named in English — names, parameters, configuration fields,")
        print("  attributes of the error types. If a hit is an English word, it belongs out of")
        print("  `GERMAN`/`STEM` (with a counter-check in `self_check_names`).\n")
    else:
        ok(f"Tiers A and B English: {n_number} names, parameters, fields and attributes, no "
           "German word")

    # The keys and values of tiers A and B are English (PO decision 2026-09-27).
    w_error, w_number = check_values(earlier_file)
    if w_error:
        red = True
        print(f"\n  {len(w_error)} keys/values of tiers A/B German or from 0.21.x "
              "(or measurement too small):\n")
        for line in w_error:
            print(f"    VALUE        {line}")
        print("\n  What the public surface returns or accepts is English — result dicts,")
        print("  event payload, context of custom pages, JSON responses, stored values. Audit")
        print("  and log lines are not meant (this check does not measure them).\n")
    else:
        ok(f"Keys and values of tiers A and B English: {w_number} measured (probe instance, "
           "constants, source), no German word, none from 0.21.x")

    # What operators and proxies read is English too: parameters, headers, cookies, loggers, log lines, ids.
    t_error, t_number = check_contract_names(earlier_file)
    if t_error:
        red = True
        print(f"\n  {len(t_error)} names of the operator contract German (or measurement too small):\n")
        for line in t_error:
            print(f"    GERMAN       {line}")
        print("\n  Query/form parameters, header and cookie names, logger names, event words and keys of the")
        print("  security log, message ids and placeholders, deployment variables, command-line options and")
        print("  the free text of the log lines are English (PO decision 2026-10-29, last breaking pass).\n")
    else:
        ok(f"Operator contract English: {t_number} names and log texts (routes, headers, cookies, loggers, log "
           "lines, message ids, deployment variables, options), no German word")

    # The operator and proxy contract (PO decision 2026-10-29): routes, forward/gate responses, hook, logs.
    v_error = contract_findings(earlier_file, now, CT.routes_live())
    if v_error:
        red = True
        print(f"\n  {len(v_error)} findings on the HTTP/log contract:\n")
        for line in v_error:
            print(f"    CONTRACT     {line}")
        print("\n  The decision of 2026-10-29 (backlog/M-1): what proxies and filters read is tier A, the")
        print("  HTML pages are tier B. A finding here is a tier that sits lower than decided, a measurement")
        print("  that shrank, or a route the static scan does not see (tests/_contract.py).\n")
    else:
        ok(f"HTTP/log contract: {len(now['http.routes'])} routes (static scan = FastAPI's reading), "
           f"{len(now['http.forward'])} observed forward/gate responses, {len(now['http.contract'])} header/"
           f"reason/input/cookie atoms, {len(now['log.loggers'])} loggers, {len(now['log.lines'])} log atoms, "
           f"{len(now['TinySesam.event_payload'])} event payloads, auth.cfg and on_security_event")

    if not breaks and not extensions:
        n = sum(len(v) for v in now.values())
        ok(f"public API unchanged ({n} names)")
        return 1 if red else 0

    print("\n  The public API has changed.\n")
    for b in breaks:
        print(f"    BREAK        {b}")
    for e in extensions:
        print(f"    Extension    {e}")
    print("\n  A break costs users work. What it costs is told by the tier before it:")
    for tier, text in TIERS.items():
        print(f"    [{tier}] {text}")
    print("  If the change was intended: `python tests/test_api_surface.py --update`, then commit")
    print("  — and point it out in the CHANGELOG if a BREAK is involved. A new name")
    print("  needs its tier afterwards.\n")
    return 1


if __name__ == "__main__":
    code = main(sys.argv[1:])
    print("\nAPI SURFACE " + ("OK ✅" if code == 0 else "CHANGED OR WITHOUT TIER ❌"))
    sys.exit(code)
