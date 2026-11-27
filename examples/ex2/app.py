"""Example Ex2 (T-100, ADR-17): a Python application with TinySesam as a library and permissions.

The application declares what it can do — `docs.read` and `docs.delete` — and asks only `has_permission`; who may is
decided in TinySesam's admin panel: the administrator assigns the permissions to roles (*Accounts → Permissions*) and the
roles to accounts. The list shows the "Delete" button only to someone holding `docs.delete`, and the delete route
checks the same permission again (a hidden button is no protection).

    python examples/ex2/app.py --demo

`--demo` starts it on http://127.0.0.1:8002 with a throwaway database and three people (password
`demo password 4711`): `ada` (administrator), `rita` (role `docs-reader`) and `eddi` (role `docs-editor`); the demo
assigns `docs.read` to both roles and `docs.delete` to `docs-editor`, as an administrator would in the panel. Nothing
leaves the machine.
"""
from __future__ import annotations

import argparse
import html
import os
import sys
import tempfile

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

APP = "docs"
#: The application's manifest: what it can do. Declaring grants nothing — the panel assigns.
PERMISSIONS = [
    {"name": "docs.read", "label": {"en": "Read documents", "de": "Dokumente lesen"},
     "suggested_roles": ["docs-reader", "docs-editor"]},
    {"name": "docs.delete", "label": {"en": "Delete documents", "de": "Dokumente löschen"}, "danger": True,
     "description": {"en": "Removes a document for everyone.", "de": "Entfernt ein Dokument für alle."},
     "suggested_roles": ["docs-editor"]},
]


def build(db_path: str, **overrides) -> "tuple[FastAPI, TinySesam]":
    """The application and its TinySesam: local accounts, the panel, the account page, and the manifest above."""
    values = dict(db_path=db_path, rp_name="Ex2", lang="en", cookie_secure=False,
                  available_roles=["docs-reader", "docs-editor"],
                  apps={APP: {"name": {"en": "Documents", "de": "Dokumente"}, "permissions": PERMISSIONS}})
    values.update(overrides)
    auth = TinySesam(TinySesamConfig(**values))
    app = FastAPI()
    app.include_router(auth.router())
    docs = {"d1": "Quarterly report", "d2": "Meeting notes", "d3": "Draft"}

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, user=Depends(auth.require_permission("docs.read", app=APP))):
        # The button follows the permission — and the route below asks again.
        may_delete = auth.has_permission(user, "docs.delete", app=APP)
        csrf = html.escape(request.cookies.get(auth.csrf_cookie_name) or "")
        rows = "".join(
            f"<li id=doc-{d}>{html.escape(title)}"
            + (f" <form method=post action='/docs/{d}/delete'><input type=hidden name=_csrf value='{csrf}'>"
               f"<button id=del-{d}>Delete</button></form>" if may_delete else "")
            + "</li>" for d, title in sorted(docs.items()))
        return (f"<!doctype html><title>Documents</title><h1>Documents</h1><p>Signed in as "
                f"{html.escape(user['username'])}</p><ul>{rows}</ul>")

    @app.post("/docs/{doc}/delete")
    def delete(request: Request, doc: str, csrf: str = Form("", alias="_csrf"),
               user=Depends(auth.require_permission("docs.delete", app=APP))):
        auth.require_csrf(request, csrf)
        docs.pop(doc, None)
        return RedirectResponse("/", 303)

    app.state.docs = docs
    return app, auth


def demo() -> None:
    import uvicorn
    app, auth = build(os.path.join(tempfile.mkdtemp(prefix="ex2-"), "ex2.db"))
    password = "demo password 4711"
    auth.create_user("ada", password=password, is_admin=True)
    auth.create_user("rita", password=password, roles=["docs-reader"])
    auth.create_user("eddi", password=password, roles=["docs-editor"])
    for role in ("docs-reader", "docs-editor"):
        auth.grant_permission(role, "docs.read", app=APP, by="demo")
    auth.grant_permission("docs-editor", "docs.delete", app=APP, by="demo")
    uvicorn.run(app, host="127.0.0.1", port=8002)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--demo", action="store_true", help="start with a throwaway database and three people")
    if parser.parse_args().demo:
        demo()
    else:
        parser.print_help()
