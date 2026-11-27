"""The store part `permissions` (schema 27, T-100, ADR-17): permissions applications declare, and which role holds which.

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the store as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import json
from typing import Optional

from . import store as _store


def sync_permissions(self, app: str, source: str, specs: list, now: Optional[int] = None) -> dict:
    """Make the manifest `specs` (checked, normalized declarations) of `source` (`config` or `app`) the truth for
    `app`, in ONE transaction: a new name is added; a known one of the same source takes the new texts; one that comes
    back after it was orphaned is current again — but its assignments stay suspended (`active` = 0, never silently
    re-granted); a name of this source that the manifest no longer names is orphaned and its assignments suspended. A
    name another source declared stays that source's. Returns `{"added", "updated", "returned", "orphaned"}` (names)."""
    now = _store._now() if now is None else int(now)
    out: dict = {"added": [], "updated": [], "returned": [], "orphaned": []}
    with self._writing():
        self._begin_immediate()
        have = {r["name"]: dict(r) for r in self.db.execute(
            "SELECT name, label, description, danger, suggested_roles, source, orphaned_at FROM app_permission "
            "WHERE app = ?", (app,))}
        named = set()
        for spec in specs:
            name = spec["name"]
            named.add(name)
            values = (json.dumps(spec["label"], sort_keys=True), json.dumps(spec["description"], sort_keys=True),
                      1 if spec["danger"] else 0, json.dumps(spec["suggested_roles"]))
            row = have.get(name)
            if row is None:
                self.db.execute("INSERT INTO app_permission(app, name, label, description, danger, suggested_roles, "
                                "source, registered_at) VALUES (?,?,?,?,?,?,?,?)", (app, name, *values, source, now))
                out["added"].append(name)
                continue
            if row["orphaned_at"] is not None:
                self.db.execute("UPDATE app_permission SET orphaned_at = NULL, source = ? WHERE app = ? AND name = ?",
                                (source, app, name))
                out["returned"].append(name)
                row["source"] = source
            if row["source"] == source and (row["label"], row["description"], row["danger"],
                                            row["suggested_roles"]) != values:
                self.db.execute("UPDATE app_permission SET label = ?, description = ?, danger = ?, suggested_roles = ? "
                                "WHERE app = ? AND name = ?", (*values, app, name))
                out["updated"].append(name)
        gone = [n for n, r in have.items() if r["source"] == source and r["orphaned_at"] is None and n not in named]
        for name in gone:
            self.db.execute("UPDATE app_permission SET orphaned_at = ? WHERE app = ? AND name = ?", (now, app, name))
            self.db.execute("UPDATE role_permission SET active = 0 WHERE app = ? AND name = ?", (app, name))
        out["orphaned"] = gone
        self.db.commit()
    return out


def permission_apps(self, source: Optional[str] = None) -> list:
    """The application ids with declared permissions (of `source`, or any), sorted."""
    where, args = ("WHERE source = ?", (source,)) if source else ("", ())
    return [r["app"] for r in self._all(f"SELECT DISTINCT app FROM app_permission {where} ORDER BY app", args)]


def active_permission_count(self, app: str, besides_source: str) -> int:
    """How many current (not orphaned) permissions of `app` another source than `besides_source` declares."""
    r = self._one("SELECT COUNT(*) AS n FROM app_permission WHERE app = ? AND source <> ? AND orphaned_at IS NULL",
                  (app, besides_source))
    return int(r["n"]) if r else 0


def app_permission_rows(self, app: str) -> list:
    """Every declared permission of `app` with its assignments: `[{"name", "label", "description", "danger",
    "suggested_roles", "source", "registered_at", "orphaned_at", "roles", "suspended_roles"}]`, sorted by name."""
    rows = [dict(r) for r in self._all("SELECT * FROM app_permission WHERE app = ? ORDER BY name", (app,))]
    held: dict = {}
    for r in self._all("SELECT role, name, active FROM role_permission WHERE app = ? ORDER BY role", (app,)):
        held.setdefault(r["name"], ([], []))[0 if r["active"] else 1].append(r["role"])
    for r in rows:
        for key in ("label", "description", "suggested_roles"):
            try:
                r[key] = json.loads(r[key])
            except (ValueError, TypeError):
                r[key] = [] if key == "suggested_roles" else {}
        r["danger"] = bool(r["danger"])
        r["roles"], r["suspended_roles"] = held.get(r["name"], ([], []))
    return rows


def get_app_permission(self, app: str, name: str) -> Optional[dict]:
    r = self._one("SELECT * FROM app_permission WHERE app = ? AND name = ?", (app, name))
    return dict(r) if r else None


def effective_permissions(self, roles, app: str) -> list:
    """The permissions of `app` the roles `roles` hold together (the union): assigned, active, not orphaned."""
    roles = sorted({r for r in roles or [] if isinstance(r, str)})
    if not roles:
        return []
    return [r["name"] for r in self._all(
        "SELECT DISTINCT name FROM role_permission JOIN app_permission USING (app, name) "
        f"WHERE app = ? AND active = 1 AND orphaned_at IS NULL AND role IN ({','.join('?' * len(roles))}) "
        "ORDER BY name", (app, *roles))]


def current_permissions(self, app: str) -> list:
    """Every current (not orphaned) permission name of `app` — what `admin_implies_permissions` gives an administrator."""
    return [r["name"] for r in self._all("SELECT name FROM app_permission WHERE app = ? AND orphaned_at IS NULL "
                                         "ORDER BY name", (app,))]


def grant_role_permission(self, role: str, app: str, name: str, by: Optional[str], now: Optional[int] = None) -> str:
    """Assign: `ok`, `exists` (already active), `missing` (not declared) or `orphaned`. A suspended assignment becomes
    active again — an administrator's explicit act. Check and write in one transaction."""
    now = _store._now() if now is None else int(now)
    with self._writing():
        self._begin_immediate()
        perm = self.db.execute("SELECT orphaned_at FROM app_permission WHERE app = ? AND name = ?",
                               (app, name)).fetchone()
        if perm is None or perm["orphaned_at"] is not None:
            self.db.rollback()
            return "missing" if perm is None else "orphaned"
        row = self.db.execute("SELECT active FROM role_permission WHERE role = ? AND app = ? AND name = ?",
                              (role, app, name)).fetchone()
        if row is not None and row["active"]:
            self.db.rollback()
            return "exists"
        self.db.execute("INSERT OR REPLACE INTO role_permission(role, app, name, active, granted_at, granted_by) "
                        "VALUES (?,?,?,1,?,?)", (role, app, name, now, by))
        self.db.commit()
    return "ok"


def has_role_permissions(self) -> bool:
    """Is any permission assigned to any role at all (the start skips the B-19 check otherwise)?"""
    return self._one("SELECT 1 AS x FROM role_permission LIMIT 1") is not None


def suspend_assignments_of_removed_roles(self, known) -> list:
    """B-19: the assignments of roles that are not in `known` (the configuration's and the catalog's roles) — every
    such row, `[{"role", "app", "name", "suspended"}]` sorted, where `suspended` is True for a row this call has just
    suspended (`active` = 0). In ONE transaction: a role created later under the same name finds them suspended and
    holds nothing until an administrator assigns again (`grant_role_permission` re-activates)."""
    known = sorted({r for r in known if isinstance(r, str)})
    marks = ",".join("?" * len(known))
    where = f"role NOT IN ({marks})" if known else "1"
    with self._writing():
        self._begin_immediate()
        rows = [dict(r) for r in self.db.execute(
            f"SELECT role, app, name, active FROM role_permission WHERE {where} ORDER BY role, app, name", known)]
        if any(r["active"] for r in rows):
            self.db.execute(f"UPDATE role_permission SET active = 0 WHERE active = 1 AND {where}", known)
        self.db.commit()
    return [{"role": r["role"], "app": r["app"], "name": r["name"], "suspended": bool(r["active"])} for r in rows]


def revoke_role_permission(self, role: str, app: str, name: str) -> bool:
    """Withdraw an assignment (also a suspended one). True if there was one."""
    return self._exec("DELETE FROM role_permission WHERE role = ? AND app = ? AND name = ?",
                      (role, app, name)).rowcount > 0


def delete_orphaned_permission(self, app: str, name: str) -> str:
    """Delete an orphaned permission and its assignments: `ok`, `missing` or `current` (still declared — refused)."""
    with self._writing():
        self._begin_immediate()
        row = self.db.execute("SELECT orphaned_at FROM app_permission WHERE app = ? AND name = ?",
                              (app, name)).fetchone()
        if row is None or row["orphaned_at"] is None:
            self.db.rollback()
            return "missing" if row is None else "current"
        self.db.execute("DELETE FROM role_permission WHERE app = ? AND name = ?", (app, name))
        self.db.execute("DELETE FROM app_permission WHERE app = ? AND name = ?", (app, name))
        self.db.commit()
    return "ok"
