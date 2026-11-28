"""Example Ex2 (T-100, ADR-17, T-103): a Python application with TinySesam as a library, permissions and the shell at
the side.

The application declares what it can do — `docs.read` and `docs.delete` — and asks only `has_permission`; who may is
decided in TinySesam's admin panel: the administrator assigns the permissions to roles (*Accounts → Permissions*) and the
roles to accounts. The list shows the "Delete" button only to someone holding `docs.delete`, and the delete route
checks the same permission again (a hidden button is no protection).

Surface "shell at the side" (T-103): `shell_layout="side"` puts TinySesam's bar at the left of every page — the
application's own (`auth.topbar(request)`, markup from TinySesam's `topbar.py`) and TinySesam's account page and panel.
The bar's links follow roles and permissions: *Editing guide* for the role `docs-editor`, *Trash* for holders of
`docs.delete`. Every page carries a strict CSP with a nonce.

    python examples/ex2/app.py --demo

`--demo` starts it on http://127.0.0.1:8002 with a throwaway database and three people (password
`demo password 4711`): `ada` (administrator), `rita` (role `docs-reader`) and `eddi` (role `docs-editor`); the demo
assigns `docs.read` to both roles and `docs.delete` to `docs-editor`, as an administrator would in the panel. Nothing
leaves the machine.

With an identity provider (optional, T-162): set `EX2_OIDC_ISSUER`, `EX2_OIDC_CLIENT_ID` and `EX2_OIDC_CLIENT_SECRET`
(the provider allows the redirect URI `http://127.0.0.1:8002/auth/oidc/callback` and sends the `groups` claim) and
`--demo` adds the provider's sign-in beside the local accounts: a person of the provider's group `readers` gets the
role `docs-reader` at every sign-in (`provider_from_env`).
"""
from __future__ import annotations

import argparse
import html
import os
import secrets
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
                  apps={APP: {"name": {"en": "Documents", "de": "Dokumente"}, "permissions": PERMISSIONS}},
                  # The shell at the side (T-103), with links by role and by permission.
                  shell_layout="side",
                  topbar_links=[("Documents", "/"), ("Editing guide", "/guide", {"role": "docs-editor"}),
                                ("Trash", "/trash", {"permission": "docs.delete", "app": APP})])
    values.update(overrides)
    auth = TinySesam(TinySesamConfig(**values))
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(auth.router())
    docs = {"d1": "Quarterly report", "d2": "Meeting notes", "d3": "Draft"}
    trash: dict = {}

    def page(request: Request, title: str, body: str, current: str) -> HTMLResponse:
        """An own page with TinySesam's bar at the side and a strict CSP: every script and style carries the nonce."""
        nonce = secrets.token_urlsafe(16)
        style = ("main{max-width:760px;margin:0 auto;padding:24px 16px;font-family:var(--ts-font);color:var(--ts-ink)}"
                 "main a{color:var(--ts-link)}main li{margin:6px 0}main form{display:inline}"
                 "body{margin:0;background:var(--ts-bg)}")
        out = HTMLResponse(
            f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>"
            f"{auth.topbar_head(nonce=nonce)}<style nonce='{nonce}'>{style}</style></head><body>"
            f"{auth.topbar(request, nonce=nonce, current=current)}<main><h1>{html.escape(title)}</h1>{body}</main>"
            "</body></html>")
        out.headers["Content-Security-Policy"] = (
            f"default-src 'self'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; img-src 'self' data:; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
        auth.ensure_csrf(request, out)       # the menu's sign-out form needs the CSRF cookie
        return out

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
        return page(request, "Documents", f"<p>Signed in as <bdi>{html.escape(user['username'])}</bdi></p>"
                                          f"<ul>{rows}</ul>", "/")

    @app.get("/guide", response_class=HTMLResponse)
    def guide(request: Request, user=Depends(auth.require(role="docs-editor"))):
        return page(request, "Editing guide", "<p>Keep titles short; drafts stay private.</p>", "/guide")

    @app.get("/trash", response_class=HTMLResponse)
    def trash_page(request: Request, user=Depends(auth.require_permission("docs.delete", app=APP))):
        rows = "".join(f"<li>{html.escape(title)}</li>" for _, title in sorted(trash.items())) or "<li>Empty</li>"
        return page(request, "Trash", f"<ul>{rows}</ul>", "/trash")

    @app.post("/docs/{doc}/delete")
    def delete(request: Request, doc: str, csrf: str = Form("", alias="_csrf"),
               user=Depends(auth.require_permission("docs.delete", app=APP))):
        auth.require_csrf(request, csrf)
        if doc in docs:
            trash[doc] = docs.pop(doc)
        return RedirectResponse("/", 303)

    app.state.docs = docs
    return app, auth


#: The demo's address, and with a provider the base of its redirect URI (`/auth/oidc/callback`).
DEMO_URL = "http://127.0.0.1:8002"
#: The variables of the optional provider (T-162); the secret only from the environment, never in the source.
PROVIDER_VARIABLES = ("EX2_OIDC_ISSUER", "EX2_OIDC_CLIENT_ID", "EX2_OIDC_CLIENT_SECRET")


def provider_from_env(env, base_url: str = DEMO_URL) -> dict:
    """The overrides for `build` that add an OpenID Connect provider beside the local accounts (T-162) — empty when
    none of `PROVIDER_VARIABLES` is set, all three or a start error otherwise. The provider's group `readers` becomes
    the role `docs-reader` at every sign-in and goes when the group goes."""
    values = {name: (env.get(name) or "").strip() for name in PROVIDER_VARIABLES}
    if not any(values.values()):
        return {}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise SystemExit(f"Ex2 with an identity provider needs {', '.join(missing)} as well "
                         f"(or none of {', '.join(PROVIDER_VARIABLES)} for local accounts only)")
    return dict(base_url=base_url, oidc_enabled=True, oidc_issuer=values["EX2_OIDC_ISSUER"],
                oidc_client_id=values["EX2_OIDC_CLIENT_ID"], oidc_client_secret=values["EX2_OIDC_CLIENT_SECRET"],
                oidc_scopes="openid profile email groups", oidc_group_role_map={"readers": "docs-reader"})


def demo() -> None:
    import uvicorn
    app, auth = build(os.path.join(tempfile.mkdtemp(prefix="ex2-"), "ex2.db"), **provider_from_env(os.environ))
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
