"""The role catalog: roles an administrator adds in the panel (or with `tinysesam roles`), so the panel offers them next
to `available_roles` without a change of the configuration.

A convenience, nothing more. The catalog grants nothing and blocks nothing: headers, the gate token, key scopes and
`has_role` read only the roles an account holds, and an administrator could set any role before. What it changes is
the list the panel offers (`known`): checkboxes, the role levels (`role_levels`) and the free-text fallback, which now
appears only when both lists are empty.

The configuration stays the truth. A role the configuration names anywhere (`config_check.configured_roles`, plus
`admin` and `__admin__`) is no catalog role: the catalog refuses it, and a catalog row whose role the configuration
names later is redundant — it may be deleted, the role stays known through the configuration.

Rules here, shared by the panel, `TinySesam.create_role`/`delete_role` and the CLI. Functions of the configuration and
a `Store`, no `TinySesam`, so the CLI works on the database file without starting one.
"""
from __future__ import annotations

import unicodedata
from typing import Optional
from urllib.parse import quote

from . import _role_levels, config_check
from .errors import RoleError
from .store import role_invalid

#: At most this many catalog rows — a guard against a runaway script, and the checkbox wall stays readable.
LIMIT = 1000
#: The longest catalog role name.
NAME_MAX = 64
#: Names the configuration owns whatever it lists: the admin flag in `Remote-Groups` and the group-map target.
RESERVED = ("admin", "__admin__")

#: The identity sources that can import their groups as roles (T-102).
SOURCES = ("oidc", "saml", "ldap")


def filter_problem(pattern) -> Optional[str]:
    """Why `pattern` is no usable filter entry, or None. An exact name, or a prefix of at least one character followed
    by one trailing `*` — `*` alone would be "everything" (use an empty filter, which keeps the limit), and a `*`
    elsewhere is no pattern this filter knows."""
    if not isinstance(pattern, str) or not pattern or pattern != pattern.strip():
        return "a non-empty name without surrounding spaces"
    if pattern == "*":
        return "\"*\" alone imports everything — leave the filter empty instead (then at most 100 groups count)"
    if "*" in pattern[:-1]:
        return "a \"*\" only at the end (a prefix)"
    return None


def filter_matches(pattern: str, name: str) -> bool:
    """Exact (`staff` matches only `staff`) or prefix (`team-*` matches `team-docs`, never `team-` itself, `team` or
    `xteam-docs`). Case counts: the role keeps the raw name, so the filter compares it raw too."""
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return len(name) > len(prefix) and name.startswith(prefix)
    return name == pattern


def group_names(source: str, groups) -> list:
    """The raw names a source delivers, de-duplicated in order. LDAP's `memberOf` holds whole DNs: the name is the value
    of the first part (`cn=team-docs,ou=groups,…` → `team-docs`) — a DN holds commas and cannot be a role."""
    from .manager import _dn_parts
    out = []
    for g in groups or []:
        name = str(g)
        if source == "ldap" and "=" in name:
            # An escaped comma stays in the value (`cn=a\,b` → `a\,b`) and is refused as a role name later.
            name = _dn_parts(name)[0].partition("=")[2].strip()
        out.append(name)
    return list(dict.fromkeys(out))


def detail(name) -> str:
    """A role name for an audit detail (`key=value` pairs separated by spaces): percent-encoded, so a space or a
    comma inside cannot open a field of its own, and reversible."""
    return quote(str(name), safe=":/-_.@+")


def name_problem(name) -> Optional[str]:
    """Why `name` cannot be a NEW catalog role, or None. Stricter than `store.role_invalid` (T-85), which existing
    configurations and data must pass: a catalog name is typed into a form, so C1 controls, format characters (bidi
    overrides, zero-width characters) and line/paragraph separators are refused too — they make two roles look
    alike in the panel — and the length is bounded."""
    if role_invalid(name):
        return "a comma, a control character, surrounding spaces or an empty name"
    if any(unicodedata.category(z) in ("Cc", "Cf", "Zl", "Zp") for z in name):
        return "an invisible or direction-changing character"
    if len(name) > NAME_MAX:
        return f"more than {NAME_MAX} characters"
    return None


def config_names(cfg) -> set:
    """Every role the configuration names, plus the reserved names."""
    return {r for _, r in config_check.configured_roles(cfg) if isinstance(r, str)} | set(RESERVED)


def catalog_names(store) -> list:
    """The catalog's names that can travel as one role — a row written by a foreign writer that breaks T-85 is never
    offered (the start names it)."""
    return [r["name"] for r in store.catalog_roles() if not role_invalid(r["name"])]


def known(cfg, store) -> list:
    """`available_roles` ∪ catalog, sorted — what the panel offers an administrator."""
    listed = [r for r in getattr(cfg, "available_roles", None) or [] if isinstance(r, str)]
    return sorted(set(listed) | set(catalog_names(store)))


def _ladders(cfg) -> list:
    return _role_levels.usable(getattr(cfg, "role_levels", None) or [])


def _entry_roles(ladder, key: str) -> list:
    return [v["role"].replace(_role_levels.PLACEHOLDER, key) for v in ladder["levels"]]


def _ladder_conflict(ladders, role: str) -> bool:
    """Would `role` be claimed by a role level entry ambiguously? Its entry's other roles must map back to the same
    ladder, level and key (`_role_levels.assign`) — `coll:a-read-read` would make an entry `a-read` whose write role
    `coll:a-read` belongs to entry `a` (the same rule `config_check` applies to `available_roles`)."""
    hit = _role_levels.assign(ladders, role)
    if hit is None:
        return False
    li, _, key = hit
    return any(_role_levels.assign(ladders, r) != (li, i, key) for i, r in enumerate(_entry_roles(ladders[li], key)))


def _check_new(cfg, store, names) -> None:
    owned = {r.casefold() for r in config_names(cfg)}
    present = {r["name"].casefold() for r in store.catalog_roles()}
    ladders = _ladders(cfg)
    for name in names:
        why = name_problem(name)
        if why:
            raise RoleError("invalid", f"Role name not allowed ({why}): {name!r}", role=name)
        if name.casefold() in owned:
            raise RoleError("in_config", f"The configuration names the role {name!r} — it is no catalog role",
                            role=name)
        if name.casefold() in present:
            raise RoleError("exists", f"The role {name!r} is in the catalog already", role=name)
        if _ladder_conflict(ladders, name):
            raise RoleError("invalid", f"The role {name!r} would belong to two role level entries", role=name)


def _add(store, names, created_by) -> None:
    result = store.add_catalog_roles(names, created_by, LIMIT)
    if result == "exists":
        raise RoleError("exists", f"The role {names[0]!r} is in the catalog already", role=names[0])
    if result == "full":
        raise RoleError("full", f"The role catalog holds {LIMIT} roles — delete unused ones first", role=names[0])


def create(cfg, store, name, created_by: Optional[str] = None) -> dict:
    """Add one role. `RoleError` for every refusal, before anything is written."""
    _check_new(cfg, store, [name])
    _add(store, [name], created_by)
    return {"name": name}


def usage_kinds(usage: dict) -> list:
    """The kinds of use (`users`, `keys`, …) that occur in a usage mapping, sorted."""
    return sorted({kind for counts in usage.values() for kind, n in counts.items() if n})


def _delete(store, names) -> None:
    result, usage = store.delete_catalog_roles_if_unused(names)
    if result == "missing":
        raise RoleError("not_found", f"Not in the role catalog: {', '.join(map(repr, names))}", role=names[0])
    if result == "in_use":
        raise RoleError("in_use", f"Still in use ({', '.join(usage_kinds(usage))}): {', '.join(map(repr, names))}",
                        usage, role=", ".join(names))


def delete(cfg, store, name) -> dict:
    """Remove one unused catalog role. A role that is one level of a role level entry whose other roles are still
    known goes only with its entry (`delete_entry`) — alone it would leave half an entry. Returns
    `{"name", "in_config"}`: `in_config` = the configuration names the role, so it stays known."""
    ladders = _ladders(cfg)
    hit = _role_levels.assign(ladders, name) if isinstance(name, str) else None
    if hit is not None:
        li, _, key = hit
        others = [r for r in _entry_roles(ladders[li], key) if r != name]
        still = set(known(cfg, store))
        if any(r in still for r in others):
            raise RoleError("in_ladder", f"The role {name!r} is one level of the entry {key!r} in "
                                         f"{ladders[li]['name']!r} — delete the whole entry", role=name)
    _delete(store, [name])
    return {"name": name, "in_config": name in config_names(cfg)}


def _ladder(cfg, ladder_name):
    for ladder in _ladders(cfg):
        if ladder["name"] == ladder_name:
            return ladder
    raise RoleError("not_found", f"No role level ladder {ladder_name!r}", role=str(ladder_name))


def create_entry(cfg, store, ladder_name, key, created_by: Optional[str] = None) -> dict:
    """A new entry of a role level ladder: every level role for `key` (`coll:b-read`, `coll:b`) in ONE transaction.
    Roles already known (configuration or catalog) are kept, the rest is added; nothing to add is `exists`."""
    ladder = _ladder(cfg, ladder_name)
    if not isinstance(key, str) or not key or key != key.strip():
        raise RoleError("invalid", f"Entry name not allowed: {key!r}", role=str(key))
    roles = _entry_roles(ladder, key)
    present = set(known(cfg, store)) | config_names(cfg)
    new = [r for r in roles if r not in present]
    if not new:
        raise RoleError("exists", f"The entry {key!r} exists already", role=key)
    _check_new(cfg, store, new)
    ladders = _ladders(cfg)
    li = next(i for i, x in enumerate(ladders) if x is ladder)
    if any(_role_levels.assign(ladders, r) != (li, i, key) for i, r in enumerate(roles)):
        raise RoleError("invalid", f"The entry {key!r} would overlap another entry", role=key)
    _add(store, new, created_by)
    return {"ladder": ladder["name"], "key": key, "roles": roles, "added": new}


def delete_entry(cfg, store, ladder_name, key) -> dict:
    """Remove every level role of an entry in ONE transaction — only when all of them are catalog roles (a role the
    configuration names would keep the entry alive) and none is in use."""
    ladder = _ladder(cfg, ladder_name)
    if not isinstance(key, str) or not key:
        raise RoleError("not_found", f"No entry {key!r}", role=str(key))
    roles = _entry_roles(ladder, key)
    owned = config_names(cfg)
    if any(r in owned for r in roles):
        raise RoleError("in_config", f"The configuration names a role of the entry {key!r}", role=key)
    catalog = set(catalog_names(store))
    mine = [r for r in roles if r in catalog]
    if not mine:
        raise RoleError("not_found", f"No entry {key!r} in the role catalog", role=key)
    _delete(store, mine)
    return {"ladder": ladder["name"], "key": key, "removed": mine}


def listing(cfg, store, accounts_only=()) -> dict:
    """What the panel's role page shows: every known role and every role only accounts hold, with its origin, its
    usage and whether it can be deleted (and why not); per ladder its templates and entries."""
    owned = config_names(cfg)
    listed = {r for r in getattr(cfg, "available_roles", None) or [] if isinstance(r, str)}
    catalog = {r["name"]: r for r in store.catalog_roles()}
    names = sorted(set(listed) | set(catalog) | set(accounts_only))
    usage = store.role_usage(names)
    ladders = _ladders(cfg)
    still = set(known(cfg, store))
    roles = []
    for name in names:
        source = ("both" if name in catalog and name in owned else "catalog" if name in catalog
                  else "config" if name in owned else "accounts")
        reason = None
        if name not in catalog:
            reason = "not_catalog"
        elif any(usage[name].values()):
            reason = "in_use"
        else:
            hit = _role_levels.assign(ladders, name)
            if hit is not None and any(r in still and r != name for r in _entry_roles(ladders[hit[0]], hit[2])):
                reason = "in_ladder"
        roles.append({"name": name, "source": source, "usage": usage[name], "deletable": reason is None,
                      "reason": reason, "invalid": role_invalid(name),
                      "created_at": catalog[name]["created_at"] if name in catalog else None})
    return {"roles": roles, "limit": LIMIT, "ladders": [
        {"name": ladder["name"], "label": _role_levels.label(ladder.get("label"), getattr(cfg, "lang", "en"),
                                                             ladder["name"]),
         "templates": [v["role"] for v in ladder["levels"]]} for ladder in ladders]}


def run(argv: list, *, prog: str, config_loader=None) -> int:
    """`tinysesam roles list|create|delete`: the catalog from the command line. Like `tinysesam accounts`, it works on
    the database file and starts no TinySesam. `create` and `delete` need the configuration (`--config`): only it says
    which roles it names (refused) and which role level entries a name would touch — without it they refuse."""
    import argparse
    import os
    import sys

    from .security import line_fixed as _z
    from .store import Store

    ap = argparse.ArgumentParser(prog=prog, description="The role catalog: roles the admin panel offers next to "
                                                        "available_roles. Adding a role grants nothing.")
    sub = ap.add_subparsers(dest="action", required=True)
    for name, text in (("list", "every known role with its origin and where it is used"),
                       ("create", "add a role to the catalog"),
                       ("delete", "remove an unused role from the catalog")):
        p = sub.add_parser(name, help=text, description=text)
        p.add_argument("--db", default="", help="the database (default: db_path of the configuration)")
        if config_loader is None:
            p.add_argument("--config", default="", required=name != "list",
                           help="your configuration as module:attr or file.py:attr — a TinySesamConfig or a TinySesam "
                                "(its configuration is taken); needed for create and delete")
        if name != "list":
            p.add_argument("name", help="the role")
    a = ap.parse_args(argv)
    cfg = None
    if config_loader is not None:
        cfg = config_loader()
    elif getattr(a, "config", ""):
        from ._diagnose import _load_config
        try:
            cfg = _load_config(a.config)
        except Exception as e:                       # noqa: BLE001 — the operator's file, any error is the answer
            print(f"--config {a.config}: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
    db = a.db or (getattr(cfg, "db_path", "") if cfg is not None else "")
    if not db:
        print("--db: the database (or a configuration with db_path)", file=sys.stderr)
        return 2
    if not os.path.exists(db):
        print(f"No database at {db}.", file=sys.stderr)
        return 1
    store = Store(db)
    if a.action == "list":
        view = listing(cfg, store, store.roles_in_use()) if cfg is not None else None
        rows = view["roles"] if view else [
            {"name": r["name"], "source": "catalog", "usage": store.role_usage([r["name"]])[r["name"]]}
            for r in store.catalog_roles()]
        if not rows:
            print("No roles.")
            return 0
        for r in rows:
            used = ", ".join(f"{k} {n}" for k, n in r["usage"].items() if n) or "unused"
            print(f"{_z(r['name']):32} {r['source']:9} {used}")
        return 0
    try:
        if a.action == "create":
            create(cfg, store, a.name, "cli")
            store.audit_log("role_created", None, None, f"name={detail(a.name)} via=cli")
            print(f"Role '{_z(a.name)}' added to the catalog.")
        else:
            res = delete(cfg, store, a.name)
            store.audit_log("role_deleted", None, None, f"name={detail(a.name)} via=cli")
            tail = " It stays known through the configuration." if res["in_config"] else ""
            print(f"Role '{_z(a.name)}' removed from the catalog.{tail}")
    except RoleError as e:
        print(f"{e.code}: {_z(str(e))}", file=sys.stderr)
        return 1
    return 0
