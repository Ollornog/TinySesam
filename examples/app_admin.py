"""Recipe: link your application's admin from TinySesam — and back (README, "Link your app's admin").

    pip install -e '.[all]'
    uvicorn examples.app_admin:app --reload                            # the application, http://127.0.0.1:8000
    uvicorn examples.app_admin:internal --host 127.0.0.1 --port 9100  # internal only, never behind the proxy

Three pieces, no extra panel tab (T-77 was rejected for this):

* **There:** the top bar of every TinySesam page (account page, admin panel, the application's own pages) carries a
  link to the application's administration — only for administrators (`{"admin": True}`); for the lead of one team
  `{"role": "teamadmin"}` instead.
* **Back:** the application's admin page links back to TinySesam's admin panel, with the address `topbar_data` reports
  (it is absolute on `base_url`, so it also works from another host).
* **The bar as data** for an interface not drawn in Python: `auth.topbar_data(account)`. Here `internal` hands it to a
  frontend server for the account ID it got from the proxy (`Remote-Id`). That app listens on 127.0.0.1 only and is
  never routed by the proxy — a check of the client address would not do: behind a proxy on the same host every request
  comes from 127.0.0.1. An application only behind the gate (no TinySesam in its process) lets its page fetch
  `/.tinysesam/topbar.json` from its own host instead.

The target checks access itself — a hidden link is a convenience, not a lock.
"""
import os
import secrets
from html import escape

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path=os.environ.get("APP_ADMIN_DB", "/tmp/tinysesam-app-admin.db"),
    rp_name="Example",
    base_url=os.environ.get("APP_ADMIN_BASE_URL", "http://127.0.0.1:8000"),
    passkey_enabled=False,      # off for a local HTTP test; enable over HTTPS / a real domain
    oidc_enabled=False,
    cookie_secure=False,        # local, without HTTPS
    available_roles=["teamadmin"],
    topbar_links=[("Home", "/"),
                  ("App admin", "/app-admin", {"admin": True}),
                  ("Team", "/team", {"role": "teamadmin"})],
))

# No /docs, /redoc, /openapi.json (they would serve TinySesam's routes without sign-in).
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(auth.router())


def page(request: Request, title: str, body: str, current: str) -> HTMLResponse:
    """An own page with TinySesam's top bar (README "Top bar")."""
    nonce = secrets.token_urlsafe(16)
    out = HTMLResponse(f"<!doctype html><html><head><title>{escape(title)}</title>{auth.topbar_head(nonce=nonce)}"
                       f"</head><body>{auth.topbar(request, nonce=nonce, current=current)}<main>{body}</main>"
                       "</body></html>")
    auth.ensure_csrf(request, out)       # the menu's sign-out form needs the CSRF cookie
    return out


@app.get("/", response_class=HTMLResponse)
def home(request: Request, user=Depends(auth.require_user)):
    return page(request, "Home", f"<h1>Hello {escape(user['username'])}</h1>", "/")


@app.get("/app-admin", response_class=HTMLResponse)
def app_admin(request: Request, user=Depends(auth.require(admin=True))):
    """The application's own administration — and the way back to TinySesam's panel."""
    panel = auth.topbar_data(user)["admin_panel"]
    back = (f"<p><a href='{escape(panel['href'])}'>Accounts and sign-in: TinySesam admin panel</a></p>"
            if panel["shown"] else "")
    return page(request, "App admin", f"<h1>App admin</h1><p>Projects, settings …</p>{back}", "/app-admin")


@app.get("/team", response_class=HTMLResponse)
def team(request: Request, user=Depends(auth.require(role="teamadmin"))):
    return page(request, "Team", "<h1>Team</h1>", "/team")


# ---- internal: the bar as data for a frontend that is not drawn in Python ----
internal = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@internal.get("/topbar/{account_id}")
def topbar_for(account_id: int):
    """What the top bar shows the account behind `Remote-Id` — for the frontend server next door."""
    account = auth.get_user(account_id)
    if account is None:
        raise HTTPException(404)
    return auth.topbar_data(account)
