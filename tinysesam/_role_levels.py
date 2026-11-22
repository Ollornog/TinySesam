"""Role levels (`role_levels`): ladders of roles the admin panel offers as one choice per entry.

A ladder names an ordered list of levels, lowest first. Each level adds ONE role template with the placeholder
`{1}`; the roles of a level are its own template and those of every level below it. With

    {"name": "collections", "levels": [{"name": "read",  "role": "coll:{1}-read"},
                                       {"name": "write", "role": "coll:{1}"}]}

and the known roles `coll:a`, `coll:a-read`, `coll:b-read`, the panel shows the entries `a` and `b`, each with the
choice "— / read / write"; `a` set to write stores `coll:a-read` and `coll:a`. Nothing else changes: an account holds
plain roles as before, `Remote-Groups`, the gate token and key scopes carry exactly the stored roles — a level is a
way to pick roles, never a role that implies others.

Pure functions of the ladders and a set of known roles (no configuration object, no database), so the panel can call
them per viewer (an administrator: `available_roles`; a delegated admin: the roles in their scope) and a role catalog
can feed them later. Malformed ladders are skipped here (fail closed); `config_check` reports them at construction.
"""
from __future__ import annotations

PLACEHOLDER = "{1}"
LADDER_KEYS = {"name", "label", "levels"}
LEVEL_KEYS = {"name", "label", "role"}


def split(template) -> tuple[str, str] | None:
    """`(prefix, suffix)` around the one `{1}` of a usable template — otherwise None. A usable template holds `{1}`
    exactly once, no other brace and at least one literal character (a bare `{1}` would match every role)."""
    if not isinstance(template, str) or template.count(PLACEHOLDER) != 1:
        return None
    prefix, suffix = template.split(PLACEHOLDER)
    if "{" in prefix + suffix or "}" in prefix + suffix or not (prefix + suffix):
        return None
    return prefix, suffix


def match(template: str, role: str) -> str | None:
    """The entry key `role` takes in `template` (non-empty), or None."""
    parts = split(template)
    if parts is None or not isinstance(role, str):
        return None
    prefix, suffix = parts
    if len(role) <= len(prefix) + len(suffix) or not role.startswith(prefix) or not role.endswith(suffix):
        return None
    return role[len(prefix):len(role) - len(suffix)]


def usable(ladders) -> list:
    """The well-formed ladders (shape only), in order. A ladder: `name`, optional `label`, at least two `levels`,
    each with `name`, `role` (a usable template, none twice in the ladder) and optional `label`."""
    out, names = [], set()
    for ladder in ladders if isinstance(ladders, list) else []:
        if not (isinstance(ladder, dict) and set(ladder) <= LADDER_KEYS and _name(ladder.get("name"))
                and ladder["name"] not in names and _label(ladder.get("label"))):
            continue
        levels = ladder.get("levels")
        if not (isinstance(levels, list) and len(levels) >= 2 and all(
                isinstance(v, dict) and set(v) <= LEVEL_KEYS and _name(v.get("name"))
                and split(v.get("role")) is not None and _label(v.get("label")) for v in levels)):
            continue
        if len({v["role"] for v in levels}) != len(levels) or len({v["name"] for v in levels}) != len(levels):
            continue
        names.add(ladder["name"])
        out.append(ladder)
    return out


def _name(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _label(value) -> bool:
    """A label is absent, a string, or a mapping language → string."""
    if value is None or isinstance(value, str):
        return True
    return isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())


def label(value, lang: str, fallback: str) -> str:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict):
        return value.get(lang) or value.get("en") or fallback
    return fallback


def _templates(ladders) -> list:
    """Every `(literal length, ladder index, level index, template)`, the most specific first: a role matching
    `coll:{1}-read` and `coll:{1}` belongs to the first (key `a` for `coll:a-read`, not `a-read`)."""
    found = [(len(v["role"]) - len(PLACEHOLDER), li, vi, v["role"])
             for li, ladder in enumerate(ladders) for vi, v in enumerate(ladder["levels"])]
    return sorted(found, key=lambda t: (-t[0], t[1], t[2]))


def assign(ladders, role: str):
    """`(ladder index, level index, key)` of the most specific template `role` matches, or None."""
    for _, li, vi, template in _templates(ladders):
        key = match(template, role)
        if key is not None:
            return li, vi, key
    return None


def entries(ladders, known) -> list:
    """Per usable ladder: its entries among `known` — `[{"key", "own": [role per level], "offer": [bool per level]}]`,
    sorted by key. `own[i]` is the role level i adds; level i is offered only when ALL roles up to it are known, so a
    delegated admin is never offered a level that reaches outside their scope (the server checks again)."""
    ladders = usable(ladders)
    known = {r for r in known or [] if isinstance(r, str)}
    keys: list[dict] = [{} for _ in ladders]
    for role in sorted(known):
        hit = assign(ladders, role)
        if hit is not None:
            keys[hit[0]].setdefault(hit[2], None)
    out = []
    for ladder, found in zip(ladders, keys):
        rows = []
        for key in sorted(found):
            own = [v["role"].replace(PLACEHOLDER, key) for v in ladder["levels"]]
            offer = [all(r in known for r in own[:i + 1]) for i in range(len(own))]
            rows.append({"key": key, "own": own, "offer": offer})
        out.append(rows)
    return out


def view(ladders, known, lang: str = "en") -> list:
    """What the panel needs to draw the ladders for one viewer: name, label, level labels and entries. A ladder
    without an entry among `known` is left out."""
    ladders = usable(ladders)
    out = []
    for ladder, rows in zip(ladders, entries(ladders, known)):
        if rows:
            out.append({"name": ladder["name"], "label": label(ladder.get("label"), lang, ladder["name"]),
                        "levels": [label(v.get("label"), lang, v["name"]) for v in ladder["levels"]],
                        "entries": rows})
    return out


def overlap(a: str, b: str) -> bool:
    """Can one role match both templates? With `{1}` non-empty: when one prefix starts the other and one suffix
    ends the other."""
    pa, pb = split(a), split(b)
    if pa is None or pb is None:
        return False
    return (pa[0].startswith(pb[0]) or pb[0].startswith(pa[0])) and (pa[1].endswith(pb[1]) or pb[1].endswith(pa[1]))
