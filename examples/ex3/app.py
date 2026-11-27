"""Example Ex3 (T-102, ADR-18 stage 1): IdP groups become roles, an administrator gives them permissions.

The same documents application as Ex2, but the people come from an OIDC identity provider and nobody assigns their roles
by hand: with `oidc_group_import` every group the provider delivers at sign-in becomes a role of the same name (here only
`team-*`, `oidc_group_import_filter`). The role shows in the panel's role catalog as "⇄ from IdP"; the administrator
assigns `docs.read` to it in the permission matrix (*Accounts → Permissions*), and the application asks only
`has_permission`. When the provider stops delivering the group, the role — and with it the permission — goes at the
next sign-in or at the session's re-check against the provider (`oidc_session_refresh_minutes`).

    EX3_ISSUER=https://idp.example.com EX3_CLIENT_ID=docs EX3_CLIENT_SECRET=… python examples/ex3/app.py

starts it on http://127.0.0.1:8003 with a throwaway database (the provider must allow the redirect URI
http://127.0.0.1:8003/auth/oidc/callback and send the `groups` claim; ask for the scope with `EX3_SCOPES`). The first
person who signs in claims the administrator with the one-time token TinySesam prints. `tests/test_example_ex3.py`
runs the whole story against a stubbed provider.
"""
from __future__ import annotations

import html
import os
import sys
import tempfile

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

APP = "docs"
#: The application's manifest. Declaring grants nothing — the administrator assigns it to a role in the panel.
PERMISSIONS = [{"name": "docs.read", "label": {"en": "Read documents", "de": "Dokumente lesen"},
                "suggested_roles": ["team-docs"]}]


def build(db_path: str, *, issuer: str, client_id: str, client_secret: str, base_url: str = "http://127.0.0.1:8003",
          **overrides) -> "tuple[FastAPI, TinySesam]":
    """The application and its TinySesam: sign-in through the provider, its `team-*` groups imported as roles, the
    session re-checked against the provider every five minutes, the panel, and the manifest above."""
    values = dict(db_path=db_path, rp_name="Ex3", lang="en", base_url=base_url,
                  cookie_secure=base_url.startswith("https://"), password_enabled=True,
                  oidc_enabled=True, oidc_issuer=issuer, oidc_client_id=client_id, oidc_client_secret=client_secret,
                  oidc_scopes="openid profile email groups", oidc_group_import=True,
                  oidc_group_import_filter=["team-*"], oidc_session_refresh_minutes=5,
                  apps={APP: {"name": {"en": "Documents", "de": "Dokumente"}, "permissions": PERMISSIONS}})
    values.update(overrides)
    auth = TinySesam(TinySesamConfig(**values))
    app = FastAPI()
    app.include_router(auth.router())
    docs = {"d1": "Quarterly report", "d2": "Meeting notes"}

    @app.get("/", response_class=HTMLResponse)
    def index(user=Depends(auth.require_permission("docs.read", app=APP))):
        rows = "".join(f"<li id=doc-{d}>{html.escape(title)}</li>" for d, title in sorted(docs.items()))
        return (f"<!doctype html><title>Documents</title><h1>Documents</h1><p>Signed in as "
                f"{html.escape(user['username'])}</p><ul>{rows}</ul>")

    return app, auth


def main() -> None:
    import uvicorn
    missing = [k for k in ("EX3_ISSUER", "EX3_CLIENT_ID", "EX3_CLIENT_SECRET") if not os.environ.get(k)]
    if missing:
        sys.exit(__doc__ + "\nmissing: " + ", ".join(missing))
    extra = {"oidc_scopes": os.environ["EX3_SCOPES"]} if os.environ.get("EX3_SCOPES") else {}
    app, _ = build(os.path.join(tempfile.mkdtemp(prefix="ex3-"), "ex3.db"), issuer=os.environ["EX3_ISSUER"],
                   client_id=os.environ["EX3_CLIENT_ID"], client_secret=os.environ["EX3_CLIENT_SECRET"], **extra)
    uvicorn.run(app, host="127.0.0.1", port=8003)


if __name__ == "__main__":
    main()
