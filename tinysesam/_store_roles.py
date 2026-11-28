"""The store part `roles`: the role catalog (schema 25).

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (
    json,
    sqlite3,
)
from typing import Optional


# ---------- the role catalog (schema 25) ----------
def catalog_roles(self) -> list:
    """The catalog, sorted by name: `[{"name", "created_at", "created_by", "source", "last_seen_at"}]` — `source` is
    None for a role an administrator or the code added, else the identity source that delivered it first (`oidc`,
    `saml`, `ldap`; schema 28, T-102) with the last sign-in that delivered it."""
    return [dict(r) for r in self._all(
        "SELECT c.name, c.created_at, c.created_by, i.source, i.last_seen_at FROM role_catalog c "
        "LEFT JOIN idp_role i ON i.name = c.name ORDER BY c.name")]


def add_catalog_roles(self, names, created_by: Optional[str], limit: int) -> str:
    """Add `names` to the catalog in ONE transaction: all or none. `"ok"`, `"exists"` when one of them (or its
    casefold) is there already — the UNIQUE indexes decide, also against a concurrent writer — or `"full"` when
    the catalog would grow past `limit`."""
    names = list(dict.fromkeys(names))
    with self._writing():
        self._begin_immediate()
        count = int(self.db.execute("SELECT COUNT(*) AS n FROM role_catalog").fetchone()["n"])
        if count + len(names) > limit:
            self.db.rollback()
            return "full"
        try:
            for name in names:
                self.db.execute("INSERT INTO role_catalog(name, name_compare, created_at, created_by) VALUES (?,?,?,?)",
                                (name, name.casefold(), _store._now(), created_by))
        except sqlite3.IntegrityError:
            self.db.rollback()
            return "exists"
        self.db.commit()
    return "ok"


def _role_usage_locked(self, names, now: int) -> dict:
    """`{name: {"users", "keys", "services", "links", "approvals", "permissions"}}` — where each of `names` is held or
    waits to be: accounts (every row), API key scopes (not revoked, not expired), OAuth service scopes (not revoked),
    open one-time tokens with roles in their payload (invitations, service pairing codes), pending approvals of
    `tinysesam.account.set_roles` that would add it, and permissions assigned to it (T-100: a role deleted and created
    anew must not inherit them). Called inside a transaction (or under `_lock`)."""
    wanted = set(names)
    out = {n: {"users": 0, "keys": 0, "services": 0, "links": 0, "approvals": 0, "permissions": 0} for n in wanted}

    def count(kind: str, raw) -> None:
        try:
            value = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            return
        for role in set(value) if isinstance(value, list) else ():
            if isinstance(role, str) and role in wanted:
                out[role][kind] += 1

    for r in self.db.execute("SELECT roles FROM users"):
        count("users", r["roles"])
    for r in self.db.execute("SELECT roles FROM api_key WHERE revoked = 0 "
                             "AND (expires_at IS NULL OR expires_at > ?)", (now,)):
        count("keys", r["roles"])
    for r in self.db.execute("SELECT roles FROM oauth_service_client "
                             "WHERE revoked_at IS NULL AND roles IS NOT NULL"):
        count("services", r["roles"])
    for r in self.db.execute("SELECT payload FROM magic_token WHERE used_at IS NULL AND expires_at > ? "
                             "AND payload IS NOT NULL", (now,)):
        try:
            payload = json.loads(r["payload"])
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict):
            count("links", payload.get("roles"))
    for r in self.db.execute("SELECT payload FROM approval WHERE state = 'pending' "
                             "AND type = 'tinysesam.account.set_roles'"):
        try:
            payload = json.loads(r["payload"])
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict):
            count("approvals", payload.get("add"))
    for r in self.db.execute(f"SELECT role, COUNT(*) AS n FROM role_permission WHERE role IN ({','.join('?' * len(wanted))}) "
                             "GROUP BY role", sorted(wanted)):
        out[r["role"]]["permissions"] += int(r["n"])
    return out


def role_usage(self, names, now: Optional[int] = None) -> dict:
    """`_role_usage_locked` for a read (the panel's list, the CLI)."""
    with self._lock:
        return self._role_usage_locked(names, _store._now() if now is None else now)


def delete_catalog_roles_if_unused(self, names, now: Optional[int] = None) -> tuple:
    """Remove `names` from the catalog only if none of them is used anywhere (`_role_usage_locked`) — check and
    delete in ONE transaction (`BEGIN IMMEDIATE`, also across processes): an account, key or invitation that gets
    one of the roles while this runs either commits before (then the role is in use and stays) or waits for the
    lock and commits after (then it holds a role the catalog no longer knows — the panel shows it under roles
    outside the configuration). Returns `("ok", usage)`, `("in_use", usage)` or `("missing", {})` when one of
    them is not in the catalog."""
    names = list(dict.fromkeys(names))
    now = _store._now() if now is None else now
    with self._writing():
        self._begin_immediate()
        have = {r["name"] for r in self.db.execute(
            f"SELECT name FROM role_catalog WHERE name IN ({','.join('?' * len(names))})", names)}
        if len(have) != len(names):
            self.db.rollback()
            return "missing", {}
        usage = self._role_usage_locked(names, now)
        self._catalog_hook()
        if any(any(v.values()) for v in usage.values()):
            self.db.rollback()
            return "in_use", usage
        self.db.executemany("DELETE FROM role_catalog WHERE name = ?", [(n,) for n in names])
        self.db.commit()
    return "ok", usage


def _catalog_hook(self) -> None:
    """Between the usage check and the delete, inside the transaction: nothing here. A test replaces it to show
    that a concurrent assignment cannot slip in between (tests/test_role_catalog.py)."""


# ---------- IdP group import (schema 28, T-102) ----------
def import_idp_roles(self, user_id, source: str, names, limit: int, now: Optional[int] = None) -> Optional[dict]:
    """Replace what `source` delivered last for this account by `names` (already filtered and checked against the
    configuration by the caller) — catalog, notes, membership and the account's roles in ONE transaction.

    * A name whose catalog row is local (no `idp_role` note) or differs only in case, or that an account holds without
      a catalog row (a role typed in by hand), collides: skipped, never merged into the local role.
    * A new name gets a catalog row (`created_by` `idp:<source>`) and its note, unless the catalog holds `limit` rows.
    * Granted: an accepted role the account lacks. Withdrawn: a role this source delivered before and no longer does —
      unless the account held it by hand when the source first delivered it, or another source still delivers it.

    Returns `{"granted", "withdrawn", "accepted", "skipped": {name: reason}}` (reason `catalog`, `case`, `accounts`,
    `full`), or None when the account does not exist."""
    now = _store._now() if now is None else now
    names = list(dict.fromkeys(str(n) for n in names))
    out: dict = {"granted": [], "withdrawn": [], "accepted": [], "skipped": {}}
    with self._writing():
        self._begin_immediate()
        row = self.db.execute("SELECT roles FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None:
            self.db.rollback()
            return None
        try:
            roles = [str(r) for r in json.loads(row["roles"] or "[]")]
        except (ValueError, TypeError):
            roles = []
        catalog = {r["name_compare"]: r for r in self.db.execute(
            "SELECT c.name, c.name_compare, i.source FROM role_catalog c LEFT JOIN idp_role i ON i.name = c.name")}
        count = len(catalog)
        held_by_hand = None
        for name in names:
            hit = catalog.get(name.casefold())
            if hit is not None:
                if hit["source"] is None:
                    out["skipped"][name] = "catalog"
                elif hit["name"] != name:
                    out["skipped"][name] = "case"
                else:
                    self.db.execute("UPDATE idp_role SET last_seen_at=? WHERE name=?", (now, name))
                    out["accepted"].append(name)
                continue
            if held_by_hand is None:
                # Roles accounts hold without a catalog row: typed in by hand, so local. Read once, only for a name the
                # catalog does not know yet (a known IdP role is not checked again).
                held_by_hand = set()
                for z in self.db.execute("SELECT roles FROM users WHERE roles IS NOT NULL AND roles NOT IN ('', '[]')"):
                    try:
                        held_by_hand |= {str(r).casefold() for r in json.loads(z["roles"]) if r}
                    except (ValueError, TypeError):
                        continue
            if name.casefold() in held_by_hand:
                out["skipped"][name] = "accounts"
                continue
            if count >= limit:
                out["skipped"][name] = "full"
                continue
            self.db.execute("INSERT INTO role_catalog(name, name_compare, created_at, created_by) VALUES (?,?,?,?)",
                            (name, name.casefold(), now, f"idp:{source}"))
            self.db.execute("INSERT INTO idp_role(name, source, last_seen_at) VALUES (?,?,?)", (name, source, now))
            catalog[name.casefold()] = {"name": name, "name_compare": name.casefold(), "source": source}
            count += 1
            out["accepted"].append(name)
        before = {r["role"]: bool(r["held_before"]) for r in self.db.execute(
            "SELECT role, held_before FROM idp_role_membership WHERE user_id=? AND source=?", (user_id, source))}
        others = {r["role"] for r in self.db.execute(
            "SELECT role FROM idp_role_membership WHERE user_id=? AND source<>?", (user_id, source))}
        new = set(out["accepted"])
        changed = False
        for role in out["accepted"]:
            if role in before:
                self.db.execute("UPDATE idp_role_membership SET seen_at=? WHERE user_id=? AND source=? AND role=?",
                                (now, user_id, source, role))
            else:
                by_hand = role in roles and role not in others
                self.db.execute("INSERT INTO idp_role_membership(user_id, source, role, held_before, seen_at) "
                                "VALUES (?,?,?,?,?)", (user_id, source, role, 1 if by_hand else 0, now))
            if role not in roles:
                roles.append(role)
                out["granted"].append(role)
                changed = True
        for role in sorted(set(before) - new):
            self.db.execute("DELETE FROM idp_role_membership WHERE user_id=? AND source=? AND role=?",
                            (user_id, source, role))
            if not before[role] and role not in others and role in roles:
                roles.remove(role)
                out["withdrawn"].append(role)
                changed = True
        if changed:
            self.db.execute("UPDATE users SET roles=? WHERE id=?", (json.dumps(roles), user_id))
        self.db.commit()
    return out


#: At most this many skipped names are kept as hints (the newest win).
IDP_NOTES_MAX = 50
#: A skipped name's hint fades after this many days unless a later sign-in skips it again.
IDP_NOTES_DAYS = 30


def idp_group_notes(self) -> dict:
    """The import's hints for the panel: `{"skipped": {name: {"source", "reason", "at"}}, "missing": {source: at},
    "over_limit": {source: {"at", "count"}}}` — each one cleared again by a later sign-in that resolves it."""
    try:
        value = json.loads(self.get_setting("idp_group_notes") or "{}")
    except (ValueError, TypeError):
        value = {}
    value = value if isinstance(value, dict) else {}
    return {k: value.get(k) if isinstance(value.get(k), dict) else {} for k in ("skipped", "missing", "over_limit")}


def note_idp_groups(self, source: str, *, skipped: Optional[dict] = None, accepted=(), missing: bool = False,
                    over: Optional[int] = None, now: Optional[int] = None) -> None:
    """Update the hints after one sign-in of `source` (read and write in ONE transaction): a missing claim or a
    group list over the limit is noted (and only that, nothing else changes); otherwise both notes of the source go,
    skipped names are noted with their reason and accepted names leave the skipped list. Writes only on a change."""
    now = _store._now() if now is None else now
    with self._writing():
        self._begin_immediate()
        row = self.db.execute("SELECT value FROM setting WHERE key='idp_group_notes'").fetchone()
        try:
            notes = json.loads(row["value"]) if row else {}
        except (ValueError, TypeError):
            notes = {}
        notes = notes if isinstance(notes, dict) else {}
        old = json.dumps(notes, sort_keys=True)
        for key in ("skipped", "missing", "over_limit"):
            if not isinstance(notes.get(key), dict):
                notes[key] = {}
        if missing:
            notes["missing"].setdefault(source, now)
        elif over is not None:
            prev = notes["over_limit"].get(source)
            notes["over_limit"][source] = {"at": prev.get("at", now) if isinstance(prev, dict) else now,
                                           "count": int(over)}
        else:
            notes["missing"].pop(source, None)
            notes["over_limit"].pop(source, None)
            for name in accepted:
                if isinstance(notes["skipped"].get(name), dict) and notes["skipped"][name].get("source") == source:
                    notes["skipped"].pop(name)
            for name, reason in (skipped or {}).items():
                was = notes["skipped"].get(name)
                # The same hint again: its time moves on at most once a day (not a write per sign-in).
                if not (isinstance(was, dict) and was.get("reason") == reason and was.get("source") == source
                        and int(was.get("at") or 0) >= now - 86400):
                    notes["skipped"][name] = {"source": source, "reason": reason, "at": now}
            # A hint nothing resolves (the provider stopped sending that name) fades after `IDP_NOTES_DAYS`.
            notes["skipped"] = {k: v for k, v in notes["skipped"].items()
                                if isinstance(v, dict) and int(v.get("at") or 0) >= now - IDP_NOTES_DAYS * 86400}
            if len(notes["skipped"]) > IDP_NOTES_MAX:
                keep = sorted(notes["skipped"].items(), key=lambda kv: -int(kv[1].get("at") or 0))[:IDP_NOTES_MAX]
                notes["skipped"] = dict(keep)
        if json.dumps(notes, sort_keys=True) != old:
            self.db.execute("INSERT OR REPLACE INTO setting(key, value) VALUES ('idp_group_notes', ?)", (json.dumps(notes),))
        self.db.commit()


def idp_role_sources(self, user_id) -> dict:
    """`{role: [source, …]}` — which identity source currently delivers which of the account's roles (T-102)."""
    out: dict = {}
    for r in self._all("SELECT role, source FROM idp_role_membership WHERE user_id=? ORDER BY role, source",
                       (user_id,)):
        out.setdefault(r["role"], []).append(r["source"])
    return out


def idp_role_deliveries(self) -> dict:
    """`{account id: {role: [{source, seen_at, held_before}, …]}}` — every role an identity source currently delivers,
    with the time of its last delivery and whether the account held it by hand before (T-135, the panel's account
    page). One query for all accounts."""
    out: dict = {}
    for r in self._all("SELECT user_id, role, source, seen_at, held_before FROM idp_role_membership "
                       "ORDER BY user_id, role, source"):
        out.setdefault(int(r["user_id"]), {}).setdefault(r["role"], []).append(
            {"source": r["source"], "seen_at": r["seen_at"], "held_before": bool(r["held_before"])})
    return out


def roles_in_use(self) -> list:
    """Every role some account carries, sorted (for the start check against `available_roles`)."""
    out: set = set()
    for z in self._all("SELECT roles FROM users WHERE roles IS NOT NULL AND roles NOT IN ('', '[]')"):
        try:
            out |= {str(r) for r in json.loads(z["roles"]) if r}
        except (ValueError, TypeError):
            continue
    return sorted(out)
