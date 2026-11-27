"""The building block `group_import`: IdP groups become roles at sign-in (T-102, ADR-18 stage 1).

Methods of `TinySesam`, loaded on first use (`TinySesam.__getattr__`, the index `manager._PARTS`) — only when a source
has `*_group_import` switched on does a sign-in call into it. Each takes the instance as `self`.

The rules, in the order they apply:

1. A missing claim (`groups is None`) changes nothing: noted, logged, nothing granted, nothing withdrawn.
2. The filter (`*_group_import_filter`: exact names, or a prefix ending in `*`) narrows the list. Without a filter a
   list of more than `LIMIT_UNFILTERED` groups is not imported at all (a provider that sends a whole directory, Entra
   group overage turned around) — the same outcome as a missing claim, with a security-log line.
3. A name that cannot travel as one role (`_role_catalog.name_problem`), that the configuration names (or `admin`,
   `__admin__`), or that a role level ladder would claim ambiguously is skipped. The store skips names the local catalog
   or an account's hand-typed role already uses (`Store.import_idp_roles`).
4. What is left replaces the source's last delivery (`idp_role_membership`).
"""
from __future__ import annotations

import logging
from typing import Optional

from . import security
from ._role_catalog import SOURCES, filter_matches, filter_problem, group_names

#: Without a filter, a sign-in that delivers more groups than this imports none of them.
LIMIT_UNFILTERED = 100
#: With a filter the operator chose the groups; this only bounds one sign-in's work (the catalog's own limit applies).
LIMIT_FILTERED = 1000
#: An IdP catalog row not delivered by any sign-in for this many days is named at start.
STALE_DAYS = 90


def _import_idp_groups(self, user_id, source: str, groups) -> Optional[dict]:
    """Apply the group import of `source` for this account (T-102) — a no-op when the source does not import. `groups`
    None = the claim was missing. Returns the store's outcome (`granted`, `withdrawn`, `accepted`, `skipped`) or None
    when nothing was imported (switched off, missing claim, over the limit)."""
    from . import _role_catalog
    cfg = self.cfg
    if source not in SOURCES or not getattr(cfg, f"{source}_group_import", False):
        return None
    if groups is None:
        security.seclog.warning("Group import (%s): the sign-in carried no group claim — the imported roles stay as they "
                                "were (user_id=%s)", source, user_id)
        self.store.note_idp_groups(source, missing=True)
        return None
    names = group_names(source, groups)
    patterns = [p for p in (getattr(cfg, f"{source}_group_import_filter", None) or []) if not filter_problem(p)]
    if patterns:
        names = [n for n in names if any(filter_matches(p, n) for p in patterns)]
    limit = LIMIT_FILTERED if patterns else LIMIT_UNFILTERED
    if len(names) > limit:
        security.seclog.warning("Group import (%s): %d groups at one sign-in, more than %d%s — nothing imported, nothing "
                                "withdrawn (user_id=%s). Set %s_group_import_filter.", source, len(names), limit,
                                "" if patterns else " without a filter", user_id, source)
        self.store.note_idp_groups(source, over=len(names))
        return None
    owned = {r.casefold() for r in _role_catalog.config_names(cfg)}
    ladders = _role_catalog._ladders(cfg)
    skipped: dict = {}
    usable = []
    for name in names:
        if _role_catalog.name_problem(name):
            skipped[name] = "invalid"
        elif name.casefold() in owned:
            skipped[name] = "config"
        elif _role_catalog._ladder_conflict(ladders, name):
            skipped[name] = "ladder"
        else:
            usable.append(name)
    out = self.store.import_idp_roles(user_id, source, usable, _role_catalog.LIMIT)
    if out is None:
        return None
    skipped.update(out["skipped"])
    out["skipped"] = skipped
    for name, reason in sorted(skipped.items()):
        security.seclog.warning("Group import (%s): group %s skipped (%s) — it collides with a role of this installation "
                                "or cannot be a role name (user_id=%s)", source, security.for_log(repr(name)), reason,
                                user_id)
    self.store.note_idp_groups(source, skipped=skipped, accepted=out["accepted"])
    if out["granted"] or out["withdrawn"]:
        u = self.store.get_user(user_id)
        detail = (f"source={source} granted={','.join(_role_catalog.detail(r) for r in out['granted'])} "
                  f"withdrawn={','.join(_role_catalog.detail(r) for r in out['withdrawn'])}")
        self.audit("idp_roles_synced", str(u["username"]) if u else None, None, detail)
    return out


def _check_idp_catalog(self) -> list:
    """At start: IdP catalog rows no sign-in delivered for `STALE_DAYS` days, and rows of a source whose import is off —
    one log line naming them (they stay; an unused one may be deleted in the panel). Returns the stale names."""
    from .store import now as _now
    rows = [r for r in self.store.catalog_roles() if r.get("source")]
    if not rows:
        return []
    cut = _now() - STALE_DAYS * 86400
    stale = sorted(r["name"] for r in rows if int(r.get("last_seen_at") or 0) < cut)
    off = sorted(r["name"] for r in rows if not getattr(self.cfg, f"{r['source']}_group_import", False))
    log = logging.getLogger("tinysesam")
    if stale:
        log.warning("Imported roles no sign-in delivered for %d days: %s. The groups may be gone at the provider; an "
                    "unused role may be deleted in the panel (Roles).", STALE_DAYS, security.for_log(", ".join(stale)))
    if off:
        log.warning("Imported roles of a source whose group import is off: %s. They stay on the accounts and are no "
                    "longer synchronised.", security.for_log(", ".join(off)))
    return stale
