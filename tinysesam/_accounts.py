"""`tinysesam accounts adopt|release|restore|list` — the operator and the accounts of applications (account API, stage B).

    tinysesam accounts list    --db auth.db [--app example]
    tinysesam accounts adopt   --db auth.db --config mod:attr --app example --with-role example-member [--dry-run]
    tinysesam accounts adopt   --db auth.db --config mod:attr --app example --user lena --user '#42'
    tinysesam accounts release --db auth.db --app example [--user lena] [--dry-run]
    tinysesam accounts restore --db auth.db lena

An application owns an account only by `users.managed_by` — set when it creates the account, or by the operator here or
in the panel ("Take over for …"). Taking over is a deliberate act: only accounts that `provisioning.adopt_refusal` lets
through (no application yet, no administrator, owner, service account or delegate, at least one role, all in the
application's allowlist) — never because an account happens to hold one of its roles. Like `passwd` and `delete`, the
command works on the database file and starts no TinySesam (no first-admin token, no demo seeding)."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Callable, Optional

from . import provisioning as _prov
from .security import line_fixed as _z


def _roles(row) -> list:
    try:
        value = json.loads(row["roles"] or "[]")
    except (ValueError, TypeError):
        return []
    return [str(r) for r in value] if isinstance(value, list) else []


def _state(row) -> str:
    if row["delete_after"]:
        return "deleting"
    return {0: "active", 3: "disabled"}.get(int(row["disabled"] or 0), "disabled_operator")


def _when(t) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(int(t), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _find(store, ref: str):
    row = store.get_user_by_name(ref)
    if row is None and ref[:1] == "#" and ref[1:].isascii() and ref[1:].isdigit():
        row = store.get_user(int(ref[1:]))
    return row


def run(argv: list, *, prog: str, config_loader: Optional[Callable[[], Any]] = None) -> int:
    """The command for both entry points: the library loads `--config`, the gateway reads its environment."""
    ap = argparse.ArgumentParser(prog=prog, description="Accounts of applications (account API): list them, take "
                                                        "accounts over for an application, release them, cancel a "
                                                        "deletion by the application.")
    sub = ap.add_subparsers(dest="action", required=True)
    texts = {"list": "the accounts applications manage, with state and the end of a pending deletion",
             "adopt": "hand accounts to an application — only those its allowlist covers completely",
             "release": "take accounts away from an application (also from one that is no longer configured)",
             "restore": "cancel a deletion by the application (also after its deadline, before the cleanup)"}
    for name, text in texts.items():
        p = sub.add_parser(name, help=text, description=text)
        p.add_argument("--db", default="", help="the database (default: db_path of the configuration)")
        if config_loader is None:
            p.add_argument("--config", default="", required=name == "adopt",
                           help="your configuration as module:attr or file.py:attr — a TinySesamConfig or a TinySesam "
                                "(its configuration is taken); needed for adopt: the allowlist")
        if name in ("list", "adopt", "release"):
            p.add_argument("--app", default="", required=name != "list", help="the application id (apps[…])")
        if name in ("adopt", "release"):
            p.add_argument("--user", action="append", default=[], help="only this account: name or #<id> (repeat)")
            p.add_argument("--dry-run", action="store_true", help="say what would change, change nothing")
        if name == "adopt":
            p.add_argument("--with-role", action="append", default=[], metavar="ROLE",
                           help="only accounts holding this role (repeat: any of them)")
        if name == "restore":
            p.add_argument("user", nargs="+", help="the account: name or #<id>")
    a = ap.parse_args(argv)

    cfg = None
    if config_loader is not None:
        cfg = config_loader()
    elif getattr(a, "config", ""):
        from ._diagnose import _load_config
        try:
            cfg = _load_config(a.config)
        except Exception as e:
            print(f"--config {a.config}: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
    db = a.db or (getattr(cfg, "db_path", "") if cfg is not None else "")
    if not db:
        print("--db: the database (or a configuration with db_path)", file=sys.stderr)
        return 2
    if not os.path.exists(db):
        print(f"No database at {db}.", file=sys.stderr)
        return 1
    from .store import Store
    store = Store(db)
    apps = _prov.normalize_apps(cfg) if cfg is not None else {}

    if a.action == "list":
        rows = [r for r in store.list_users() if r["managed_by"] and (not a.app or r["managed_by"] == a.app)]
        if not rows:
            print("No accounts of applications." if not a.app else f"No accounts of '{_z(a.app)}'.")
            return 0
        for r in sorted(rows, key=lambda x: int(x["id"])):
            app_id = str(r["managed_by"])
            known = "" if cfg is None or app_id in apps else " (not configured)"
            until = f" until {_when(r['delete_after'])}" if r["delete_after"] else ""
            print(f"#{int(r['id']):<6} {_z(r['username']):24} {_z(app_id)}{known}  {_state(r)}{until}")
        return 0

    if a.action == "restore":
        failed = 0
        for ref in a.user:
            row = _find(store, ref)
            if row is None or not row["delete_after"] or not store.cancel_deletion(int(row["id"])):
                print(f"'{_z(ref)}': no account being deleted.", file=sys.stderr)
                failed += 1
                continue
            store.audit_log("provision_restore", str(row["username"]), None,
                            f"uid={int(row['id'])} by=operator source=cli")
            print(f"Deletion of '{_z(row['username'])}' (id {int(row['id'])}) cancelled.")
        return 1 if failed else 0

    if a.action == "release":
        if a.user:
            rows = []
            for ref in a.user:
                row = _find(store, ref)
                if row is None or row["managed_by"] != a.app:
                    print(f"'{_z(ref)}': not an account of '{_z(a.app)}'.", file=sys.stderr)
                    return 1
                rows.append(row)
        else:
            rows = [r for r in store.list_users() if r["managed_by"] == a.app]
        done = 0
        for row in rows:
            if a.dry_run:
                print(f"would release #{int(row['id'])} {_z(row['username'])}")
                continue
            if store.release_account(int(row["id"]), a.app):
                store.audit_log("account_released", str(row["username"]), None,
                                f"uid={int(row['id'])} app={a.app} source=cli")
                print(f"released #{int(row['id'])} {_z(row['username'])}")
                done += 1
        print(f"{len(rows)} account(s) {'would be ' if a.dry_run else ''}released from '{_z(a.app)}'"
              + ("" if a.dry_run else f" ({done} changed)") + ".")
        return 0

    # adopt
    app = apps.get(a.app)
    if app is None:
        print(f"'{_z(a.app)}' is no application with provisioning in this configuration.", file=sys.stderr)
        return 1
    if not a.user and not a.with_role:
        print("Name the accounts: --with-role ROLE and/or --user NAME — adopt never takes every account at once.",
              file=sys.stderr)
        return 2
    raw = getattr(cfg, "admin_delegates", None) or {}
    delegates = frozenset(r for r in raw if isinstance(r, str)) if isinstance(raw, dict) else frozenset()
    if a.user:
        candidates = []
        for ref in a.user:
            row = _find(store, ref)
            if row is None:
                print(f"'{_z(ref)}': no such account.", file=sys.stderr)
                return 1
            candidates.append(row)
    else:
        candidates = list(store.list_users())
    if a.with_role:
        wanted = set(a.with_role)
        candidates = [r for r in candidates if wanted & set(_roles(r))]
    taken = skipped = 0
    for row in sorted(candidates, key=lambda x: int(x["id"])):
        why = _prov.adopt_refusal(app, row, _roles(row), delegates)
        label = f"#{int(row['id'])} {_z(row['username'])}"
        if why is not None:
            print(f"skipped {label}: {why}")
            skipped += 1
            continue
        if a.dry_run:
            print(f"would adopt {label}")
            taken += 1
            continue
        if store.adopt_account(int(row["id"]), app["id"]):
            store.audit_log("account_adopted", str(row["username"]), None,
                            f"uid={int(row['id'])} app={app['id']} source=cli")
            print(f"adopted {label}")
            taken += 1
    print(f"{taken} account(s) {'would be ' if a.dry_run else ''}adopted for '{app['id']}', {skipped} skipped.")
    return 0
