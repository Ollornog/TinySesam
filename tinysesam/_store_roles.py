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
    """The catalog, sorted by name: `[{"name", "created_at", "created_by"}]`."""
    return [dict(r) for r in self._all("SELECT name, created_at, created_by FROM role_catalog ORDER BY name")]


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
    """`{name: {"users", "keys", "services", "links", "approvals"}}` — where each of `names` is held or waits to
    be: accounts (every row), API key scopes (not revoked, not expired), OAuth service scopes (not revoked), open
    one-time tokens with roles in their payload (invitations, service pairing codes) and pending approvals of
    `tinysesam.account.set_roles` that would add it. Called inside a transaction (or under `_lock`)."""
    wanted = set(names)
    out = {n: {"users": 0, "keys": 0, "services": 0, "links": 0, "approvals": 0} for n in wanted}

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


def roles_in_use(self) -> list:
    """Every role some account carries, sorted (for the start check against `available_roles`)."""
    out: set = set()
    for z in self._all("SELECT roles FROM users WHERE roles IS NOT NULL AND roles NOT IN ('', '[]')"):
        try:
            out |= {str(r) for r in json.loads(z["roles"]) if r}
        except (ValueError, TypeError):
            continue
    return sorted(out)
