"""Configuration rules for roles: the role catalog, delegated admins and their scopes (`may_manage`), role-level ladders.

Split from `config_check.py` (T-112); `config_check` re-exports what other modules and the tests take from it
(its `__all__`), so they keep `config_check.<name>`.
"""
from __future__ import annotations

from . import _role_levels
from .store import role_invalid

from ._config_check_base import (
    _an,
    _t,
)


def _mapped_roles(config) -> list:
    """The roles the group maps assign (`oidc_/saml_/ldap_group_role_map`, the maps per OIDC client) — without the
    admin target `__admin__`, which is a flag, not a role."""
    maps = [getattr(config, "oidc_group_role_map", None) or {}, getattr(config, "saml_group_role_map", None) or {},
            getattr(config, "ldap_group_role_map", None) or {}]
    maps += [dict(e or {}).get("group_role_map") or {} for e in (getattr(config, "oidc_clients", None) or {}).values()
             if isinstance(e, dict)]
    return sorted({str(r) for m in maps if isinstance(m, dict) for r in m.values() if r and r != "__admin__"})


def configured_roles(config) -> list:
    """Every `(field, role)` the configuration names as a role, in a stable order: `available_roles`,
    `signup_default_roles`, the targets of the group maps (also per OIDC client, without the flag `__admin__`), the
    delegate roles of `admin_delegates` with their `roles` and `manages`, the roles the top bar and menu links are
    shown to, and the allowlists and `approver_role` of `apps[…].provisioning`. Non-strings are left to the shape
    checks of each field. One list for the name check (T-85) and for what the configuration owns."""
    out: list = []

    def strings(field: str, values) -> None:
        for v in values if isinstance(values, (list, tuple)) else []:
            out.append((field, v))

    strings("available_roles", getattr(config, "available_roles", None))
    strings("signup_default_roles", getattr(config, "signup_default_roles", None))
    for field, m in (("oidc_group_role_map", getattr(config, "oidc_group_role_map", None)),
                     ("saml_group_role_map", getattr(config, "saml_group_role_map", None)),
                     ("ldap_group_role_map", getattr(config, "ldap_group_role_map", None))):
        if isinstance(m, dict):
            strings(field, [r for r in m.values() if r != "__admin__"])
    clients = getattr(config, "oidc_clients", None)
    for key, entry in (clients.items() if isinstance(clients, dict) else []):
        m = entry.get("group_role_map") if isinstance(entry, dict) else None
        if isinstance(m, dict):
            strings(f"oidc_clients[{key!r}].group_role_map", [r for r in m.values() if r != "__admin__"])
    delegates = getattr(config, "admin_delegates", None)
    for role, entry in (delegates.items() if isinstance(delegates, dict) else []):
        out.append(("admin_delegates", role))
        if isinstance(entry, dict):
            strings(f"admin_delegates[{role!r}].roles", entry.get("roles"))
            strings(f"admin_delegates[{role!r}].manages", entry.get("manages"))
    for field, links in (("topbar_links", getattr(config, "topbar_links", None)),
                         ("topbar_menu_links", getattr(config, "topbar_menu_links", None))):
        for link in links if isinstance(links, (list, tuple)) else []:
            rule = link[2] if isinstance(link, (list, tuple)) and len(link) == 3 else None
            if isinstance(rule, dict) and set(rule) == {"role"}:
                out.append((field, rule["role"]))
    apps = getattr(config, "apps", None)
    for app_id, entry in (apps.items() if isinstance(apps, dict) else []):
        block = entry.get("provisioning") if isinstance(entry, dict) else None
        if isinstance(block, dict):
            strings(f"apps[{app_id!r}].provisioning.roles", block.get("roles"))
            if "approver_role" in block:
                out.append((f"apps[{app_id!r}].provisioning.approver_role", block["approver_role"]))
    return out


def _role_names(config, error: list) -> None:
    """Role names that cannot travel as one role (T-85, `store.role_invalid`): a comma, a control character,
    surrounding spaces or an empty name — wherever the configuration names a role. `Remote-Groups` and `ts_groups`
    join roles with `,` without an escape, and a gate client trims the spaces around an entry: `staff,admin` would
    arrive as `admin`. A group map that assigns such a role would hand it to everyone in the group. The provisioning
    fields keep their own, more specific findings (`_provisioning_apps`, `_approver_roles`)."""
    seen: set = set()
    for field, role in configured_roles(config):
        if field.startswith("apps[") or not isinstance(role, str) or (field, role) in seen:
            continue
        seen.add((field, role))
        if role_invalid(role):
            error.append(_t(config, "{field}: the role {role!r} is empty, holds a comma or a control character, or has "
                                    "surrounding spaces — Remote-Groups would read it as another role or as several",
                            field=field, role=role))


def _roles_without_list(config, warnings: list) -> None:
    """Roles are in use, but `available_roles` is empty: the admin panel then offers a free-text field for roles
    instead of checkboxes (`admin.py`, `ROLES`), and a typo there silently creates a role nothing checks. The group
    maps show it in the configuration; roles already stored in accounts are reported at start (`TinySesam`)."""
    if not _an(config, "admin_enabled") or getattr(config, "available_roles", None):
        return
    roles = _mapped_roles(config)
    if roles:
        warnings.append(_t(
            config,
            "The group maps assign the roles {roles}, but available_roles is empty: the admin panel then "
            "offers a free-text field instead of checkboxes, and a typo there creates a role nothing checks. "
            "List the roles in available_roles.",
            roles=", ".join(roles)))


#: What a delegate role may do (T-74); `can` narrows it to a part.
DELEGATE_ACTIONS = ("create", "invite", "disable", "roles", "signin_link", "permissions")
_DELEGATE_KEYS = {"roles", "manages", "can", "apps"}


def _strings(entry: dict, name: str) -> list:
    value = entry.get(name)
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def delegation_graph(raw) -> dict:
    """The delegated administration of `admin_delegates` (T-74) — computed once per configuration state.

    `{role: {"eff": …, "desc": …, "anc": …, "can": …}}` (frozensets) for every usable delegate role:

    * `desc` — every delegate role below it, transitively through `manages` (a DAG, several parents allowed);
    * `eff` — the roles it manages: its own `roles`, the delegate roles in `desc` (it appoints and removes them)
      and their `roles`: `eff(D) = roles(D) ∪ desc(D) ∪ ⋃ roles(K), K ∈ desc(D)`;
    * `anc` — every delegate role above it;
    * `can` — its actions (`DELEGATE_ACTIONS`, all without `can`), never inherited up or down;
    * `apps` — the applications whose permissions it assigns to the roles it manages (T-100, its area; with the action
      `permissions`), never inherited either.

    Fail-closed for what `config_check` reports at construction (a configuration changed at runtime is not
    re-checked): a malformed entry and a role on a cycle get no entry and so no rights, a `manages` target that is
    no delegate role and a delegate role inside a `roles` list are ignored, an unknown `can` value counts for
    nothing."""
    if not isinstance(raw, dict):
        return {}
    delegates = {d for d in raw if isinstance(d, str) and d.strip()}
    own, manages, can, area = {}, {}, {}, {}
    for d in delegates:
        entry = raw[d]
        if not isinstance(entry, dict):
            continue
        own[d] = frozenset(r for r in _strings(entry, "roles") if r not in delegates)
        area[d] = frozenset(_strings(entry, "apps"))
        manages[d] = [k for k in _strings(entry, "manages") if k in delegates]
        can[d] = (frozenset(DELEGATE_ACTIONS) if "can" not in entry
                  else frozenset(a for a in _strings(entry, "can") if a in DELEGATE_ACTIONS))
    below = {}
    for d in own:
        seen: set = set()
        todo = list(manages[d])
        while todo:
            k = todo.pop()
            if k not in seen:
                seen.add(k)
                todo.extend(manages.get(k, []))
        below[d] = seen
    usable = {d for d in own if d not in below[d]}            # a role on a cycle reaches itself
    graph = {}
    for d in usable:
        desc = frozenset(k for k in below[d] if k in usable)
        graph[d] = {"desc": desc, "can": can[d], "apps": area[d],
                    "eff": frozenset(own[d] | desc | {r for k in desc for r in own[k]}),
                    "anc": frozenset(e for e in usable if d in below[e])}
    return graph


def delegate_scopes(graph: dict, roles) -> list:
    """The scopes of an account that holds `roles`, under a `delegation_graph` (T-74) — one `(role, managed, can)`
    per delegate role it holds, sorted; empty if it holds none.

    A pure function of the delegation and the account's roles (no configuration, no database), so it can be called
    for any delegation — e.g. one per tenant later. The caller decides first whether the account counts at all
    (a browser session, not an administrator). Never the own delegate role and none above it: an account holding
    `area-admin` and `team-a-admin` treats other `team-a-admin` accounts as peers."""
    held = sorted({r for r in roles or [] if isinstance(r, str) and r in graph})
    barred = set(held) | {a for r in held for a in graph[r]["anc"]}
    return [(r, frozenset(graph[r]["eff"] - barred), graph[r]["can"]) for r in held]


def may_manage(managed, actor_id, target, target_roles, *, delegate_roles=frozenset(),
               without_roles: bool = False) -> bool:
    """May a scope with the roles `managed` act on the whole of `target` (an account row or dict) whose roles are
    `target_roles`? Only when ALL its roles stand in `managed` — never an admin, owner or service account, never the
    actor's own (`actor_id`; None for an application, which has no account of its own among the targets), never an
    account holding a delegate role (`delegate_roles`, the keys of `admin_delegates`) that `managed` does not hold.
    Strict on purpose: locking or a sign-in link acts on the whole account, also on the parts of another team.

    The ONE rule of two entrances: a delegate in the panel (T-74, `managed` = the delegate scope, which holds exactly
    the delegate roles below it) and an application through the account API (`managed` = its allowlist,
    `actor_id=None`). `without_roles=True` lets an account without roles pass — only for the account API, whose
    accounts belong to the application by `users.managed_by`, not by their roles; for a delegate an account without
    roles stays outside (the empty set would be "inside" every scope). Pure, like `delegate_scopes`."""
    if target is None or target["is_admin"] or target["is_owner"] or target["is_service"]:
        return False
    if actor_id is not None and target["id"] == actor_id:
        return False
    if not all(isinstance(r, str) for r in target_roles or []):
        return False
    if not target_roles and not without_roles:
        return False
    if any(r in delegate_roles and r not in managed for r in target_roles or []):
        return False
    return set(target_roles or []) <= managed


def delegate_may_manage(managed, actor_id, target, target_roles) -> bool:
    """`may_manage` for a delegate scope (T-74) — the name the panel used before the account API shared the rule."""
    return may_manage(managed, actor_id, target, target_roles)


def app_visible(app_id: str, target, target_roles, delegate_roles=frozenset()) -> bool:
    """Does an application see `target` through the account API? Only an account it created (`users.managed_by` =
    `app_id`) that is no admin, owner or service account and holds no delegate role. Everything else answers like
    an account that does not exist (404). Whole-account actions additionally need `may_manage` (all roles in the
    allowlist). Pure."""
    if target is None or target["is_admin"] or target["is_owner"] or target["is_service"]:
        return False
    try:
        owner = target["managed_by"]
    except (KeyError, IndexError):
        return False
    if not owner or owner != app_id:
        return False
    return not any(isinstance(r, str) and r in delegate_roles for r in target_roles or [])


def _admin_delegates(config, error: list, warnings: list) -> None:
    """Delegated admins (T-74): the shape, every role known, no delegate role in a `roles` list, `manages` only to
    delegate roles and without a cycle, `can` only known actions.

    A delegate role in a `roles` list would let a delegate appoint delegates outside the hierarchy — appointing goes
    only through `manages`, where the cycle check keeps a role from ending up above itself. The role `admin` would
    read as the admin flag in `Remote-Groups`. A role outside `available_roles` is a typo nobody notices: the panel
    offers only listed roles as checkboxes."""
    raw = getattr(config, "admin_delegates", None)
    if not raw:
        return
    if not isinstance(raw, dict):
        error.append(_t(config, "admin_delegates: {v!r} — a mapping of delegate role → {{\"roles\": [role, …]}} "
                                "with optional \"manages\" (delegate roles below it) and \"can\" (a part of the "
                                "actions); at least one role or one managed delegate role", v=raw))
        return
    known = set(getattr(config, "available_roles", None) or [])
    for role, entry in raw.items():
        good = (isinstance(role, str) and bool(role.strip()) and isinstance(entry, dict) and "roles" in entry
                and set(entry) <= _DELEGATE_KEYS)
        if good:
            for name in _DELEGATE_KEYS & set(entry):
                value = entry[name]
                good = good and isinstance(value, list) and all(isinstance(x, str) and x.strip() for x in value) \
                    and (bool(value) or name == "roles")
            good = good and bool(entry["roles"] or entry.get("manages"))
        if not good:
            error.append(_t(config, "admin_delegates: {v!r} — a mapping of delegate role → {{\"roles\": [role, …]}} "
                                    "with optional \"manages\" (delegate roles below it) and \"can\" (a part of the "
                                    "actions); at least one role or one managed delegate role", v={role: entry}))
            continue
        if role == "admin":
            error.append(_t(config, "admin_delegates: {role!r} is not a delegate role — \"admin\" is how forward auth "
                                    "names the admin flag in Remote-Groups", role=role))
        for name in [role] + entry["roles"]:
            if name not in known:
                error.append(_t(config, "admin_delegates: the role {role!r} is not in available_roles — list every "
                                        "delegate role and every role it manages there", role=name))
        for name in entry["roles"]:
            if name in raw:
                error.append(_t(config, "admin_delegates: the delegate role {role!r} stands in the roles of {owner!r} "
                                        "— a delegate role is appointed only through \"manages\"",
                                role=name, owner=role))
        for name in entry.get("manages") or []:
            if name not in raw:
                error.append(_t(config, "admin_delegates: {owner!r} manages {role!r}, which is not a delegate role — "
                                        "\"manages\" names delegate roles (keys of admin_delegates)",
                                role=name, owner=role))
        _raw_apps = getattr(config, "apps", None)
        apps: dict = _raw_apps if isinstance(_raw_apps, dict) else {}
        for name in entry.get("apps") or []:
            if name not in apps:
                error.append(_t(config, "admin_delegates: {owner!r} names the application {app!r} in \"apps\", which "
                                        "is not in apps — the area of a delegate is a list of application ids",
                                owner=role, app=name))
        for name in entry.get("can") or []:
            if name not in DELEGATE_ACTIONS:
                error.append(_t(config, "admin_delegates: {owner!r} can {action!r}, which is no action — allowed are "
                                        "{actions}", owner=role, action=name, actions=", ".join(DELEGATE_ACTIONS)))
    # A cycle (also a role managing itself, also over several steps) would put a delegate above themselves.
    managed = {d: [k for k in _strings(e, "manages") if k in raw] for d, e in raw.items() if isinstance(e, dict)}
    for role in managed:
        seen: set = set()
        todo = list(managed[role])
        while todo:
            k = todo.pop()
            if k not in seen:
                seen.add(k)
                todo.extend(managed.get(k, []))
        if role in seen:
            error.append(_t(config, "admin_delegates: {role!r} manages itself through \"manages\" (a cycle) — "
                                    "a delegate role is never above itself", role=role))
    if not _an(config, "admin_enabled"):
        warnings.append(_t(config, "admin_delegates is set, but admin_enabled=False: the panel is not mounted at "
                                   "admin_path. Mount auth.admin_router() yourself, or delegates have no panel."))


def _role_level_ladders(config, error: list, warnings: list) -> None:
    """Role levels (`role_levels`): the shape, every template usable, no ladder with fewer than two levels, no template
    twice in a ladder, no two templates that could claim the same role ambiguously — and, as warnings, what the panel
    could not offer: a ladder without an entry, an entry missing the role of a level, a delegate holding only a part
    of a level.

    The panel skips a malformed ladder (`_role_levels.usable`, fail closed); here it is a start error, so a typo does
    not silently turn a ladder back into plain checkboxes. Ambiguity is an error and not a warning: the panel would
    store the roles of one entry for another."""
    raw = getattr(config, "role_levels", None)
    if not raw:
        return
    def shape(value) -> str:
        return _t(config, "role_levels: {v!r} — a list of ladders {{\"name\": …, \"label\": …, \"levels\": [{{\"name\": "
                          "…, \"label\": …, \"role\": \"prefix{{1}}suffix\"}}, …]}}, at least two levels, names and templates unique",
                  v=value)
    if not isinstance(raw, list):
        error.append(shape(raw))
        return
    good, names = [], set()
    for ladder in raw:
        if not _role_levels.usable([ladder]) or ladder.get("name") in names:
            error.append(shape(ladder))
            continue
        names.add(ladder["name"])
        for level in ladder["levels"]:
            if role_invalid(level["role"]):
                error.append(_t(config, "role_levels: {ladder!r} level {level!r}: the role {role!r} holds a comma or a "
                                        "control character — Remote-Groups would read it as other roles",
                                ladder=ladder["name"], level=level["name"], role=level["role"]))
        good.append(ladder)
    templates = [(ladder["name"], level["role"]) for ladder in good for level in ladder["levels"]]
    for i, (la, ta) in enumerate(templates):
        for lb, tb in templates[i + 1:]:
            if not _role_levels.overlap(ta, tb):
                continue
            if la != lb:
                error.append(_t(config, "role_levels: the templates {a!r} ({la!r}) and {b!r} ({lb!r}) can match the "
                                        "same role — every role belongs to one ladder at most",
                                a=ta, la=la, b=tb, lb=lb))
            elif len(ta) == len(tb):
                error.append(_t(config, "role_levels: {ladder!r}: the templates {a!r} and {b!r} can match the same role "
                                        "and are equally specific — which entry a role belongs to would be a guess",
                                ladder=la, a=ta, b=tb))
    known = [r for r in getattr(config, "available_roles", None) or [] if isinstance(r, str)]
    known_set = set(known)
    graph = delegation_graph(getattr(config, "admin_delegates", None))
    for ladder, rows in zip(good, _role_levels.entries(good, known)):
        for row in rows:
            for i, role in enumerate(row["own"]):
                hit = _role_levels.assign(good, role) if role in known_set else None
                if hit is not None and (good[hit[0]] is not ladder or hit[1] != i or hit[2] != row["key"]):
                    error.append(_t(config, "role_levels: {ladder!r}: the role {role!r} belongs to the entry {key!r} "
                                            "and to another one — rename the role or the template",
                                    ladder=ladder["name"], role=role, key=row["key"]))
            for delegate, node in sorted(graph.items()):
                held = [r for r in row["own"] if r in node["eff"]]
                if held and any(r not in node["eff"] for r in row["own"][:row["own"].index(held[-1]) + 1]):
                    warnings.append(_t(config, "role_levels: the delegate role {delegate!r} manages {held} but not "
                                               "every role below — it cannot grant that level of {key!r}",
                                       delegate=delegate, held=", ".join(held), key=row["key"]))


def ladder_coverage(config, known) -> list:
    """What the panel could not offer of the role levels, over the roles it knows (`available_roles` ∪ the role
    catalog): a ladder without an entry, an entry missing the role of a level. Warnings TinySesam logs at start — not
    part of `check_config`, which has no database and would report entries that come from the catalog as missing."""
    good = _role_levels.usable(getattr(config, "role_levels", None) or [])
    known = [r for r in known or [] if isinstance(r, str)]
    known_set = set(known)
    out = []
    for ladder, rows in zip(good, _role_levels.entries(good, known)):
        if not rows:
            out.append(_t(config, "role_levels: {ladder!r} has no entry among the known roles (available_roles, role "
                                  "catalog) — the panel shows no levels for it", ladder=ladder["name"]))
        for row in rows:
            missing = [r for r in row["own"] if r not in known_set]
            if missing:
                out.append(_t(config, "role_levels: {ladder!r} entry {key!r}: {roles} not among the known roles — the "
                                      "levels from there up are not offered",
                              ladder=ladder["name"], key=row["key"], roles=", ".join(missing)))
    return out


def _group_import(config, error: list, warnings: list) -> None:
    """The group import (T-102): every filter entry an exact name or a prefix with one trailing `*` (`*` alone would
    import everything without the limit), the labels plain text, and no switch without its source — nor a filter
    without its switch (a setting nothing reads). A filter entry the configuration names as a role would only ever be
    skipped."""
    from ._role_catalog import filter_problem
    owned = {str(r).casefold() for _, r in configured_roles(config) if isinstance(r, str)} | {"admin", "__admin__"}
    # Each field by its literal name (the read paths stay greppable, `tests/test_security_findings.py`).
    switches = (("oidc", getattr(config, "oidc_group_import", False), getattr(config, "oidc_group_import_filter", None),
                 _an(config, "oidc_enabled")),
                ("saml", getattr(config, "saml_group_import", False), getattr(config, "saml_group_import_filter", None),
                 _an(config, "saml_enabled")),
                ("ldap", getattr(config, "ldap_group_import", False), getattr(config, "ldap_group_import_filter", None),
                 _an(config, "ldap_enabled")))
    for source, on, patterns, source_on in switches:
        if not isinstance(on, bool):
            error.append(_t(config, "{field}={v!r} — True or False", field=f"{source}_group_import", v=on))
            continue
        patterns = patterns or []
        if not isinstance(patterns, (list, tuple)):
            error.append(_t(config, "{field}: a list of group names or prefixes ending in \"*\"",
                            field=f"{source}_group_import_filter"))
            continue
        for p in patterns:
            why = filter_problem(p)
            if why:
                error.append(_t(config, "{field}: {p!r} — {why}", field=f"{source}_group_import_filter", p=p, why=why))
            elif on and not p.endswith("*") and p.casefold() in owned:
                warnings.append(_t(config, "{field} names {p!r}, a role of the configuration: that group is always "
                                           "skipped — an IdP group never takes over a configured role",
                                   field=f"{source}_group_import_filter", p=p))
        if on and not source_on:
            warnings.append(_t(config, "{field}=True, but {source}_enabled is off: nothing is imported",
                               field=f"{source}_group_import", source=source))
        if patterns and not on:
            warnings.append(_t(config, "{field} is set, but {source}_group_import is off: the filter has no effect",
                               field=f"{source}_group_import_filter", source=source))
    labels = getattr(config, "idp_group_labels", None) or {}
    if not isinstance(labels, dict):
        error.append(_t(config, "idp_group_labels: a mapping group → display name"))
        return
    for group, label in labels.items():
        if (not isinstance(group, str) or not group or not isinstance(label, str) or not 1 <= len(label) <= 80
                or any(z < " " or z == "\x7f" for z in label)):
            error.append(_t(config, "idp_group_labels: {g!r} — a group name and a display name of 1 to 80 characters "
                                    "without control characters", g=group))
