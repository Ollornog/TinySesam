"""T-15: The built-in pages under a subpath (`root_path`) — measured on real mounts.

Three setups, the same walkthrough (login, registration, sign-in link, reset, account, admin panel,
logout, protected page):

* **Mount** — `Starlette(routes=[Mount("/sso", app)])`, the way a host app mounts TinySesam.
* **uvicorn --root-path** — the proxy strips `/sso`, uvicorn sets `root_path="/sso"` and
  builds `scope["path"] = root_path + received path` (uvicorn/protocols/http/h11_impl.py). Exactly
  that is what the wrapper `_like_uvicorn` below does; a real server would be the same scope with more waiting.
* **Root** — without prefix: nothing may have changed here.

The effect is measured, not the source text: every root-absolute reference of a page (href,
action, fetch/J call) and every redirect must begin with the prefix, and the placeholder
`__TS_P__` must arrive nowhere.
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.routing import Mount  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.templates import PREFIX_PLACEHOLDER  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Unterpfad (T-15) — eingebaute Seiten unter root_path")
PW = "Unterpfad-Test-Passwort-1"
HTML = {"accept": "text/html"}
REFERENCE = re.compile(r"""(?:href|action)=['"](/[^'"]*)['"]|(?:fetch|J)\(\s*'(/[^']*)'""")


def _setup(prefix: str):
    """TinySesam + protected page; `prefix` only for base_url (the mails)."""
    mails: list = []
    cfg = TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                          csrf_enabled=False, passkey_enabled=False, allow_signup=True,
                          password_reset_enabled=True, magiclink_enabled=True, pin_enabled=True,
                          base_url=f"https://example.com{prefix}", lang="de")
    auth = TinySesam(cfg)
    auth.set_mailer(lambda to, subject, text, html=None: mails.append(text))
    auth.ensure_admin("chefin", PW)
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/app")
    def _app(user=Depends(auth.require_user)):
        return {"u": user["username"]}
    return auth, app, mails


def _like_uvicorn(inner, root_path: str):
    """This is how uvicorn builds the scope with `--root-path`: the path gets the prefix prepended."""
    async def shell(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope = dict(scope, root_path=root_path, path=root_path + scope["path"],
                         raw_path=root_path.encode() + scope.get("raw_path", scope["path"].encode()))
        await inner(scope, receive, send)
    return shell


def _check_page_html(was: str, response, prefix: str, error: list) -> None:
    text = response.text
    if PREFIX_PLACEHOLDER in text:
        error.append(f"{was}: Platzhalter sickert durch")
    for a, b in REFERENCE.findall(text):
        destination = a or b
        if prefix and not destination.startswith(prefix + "/"):
            error.append(f"{was}: {destination!r}")
        if not prefix and destination.startswith("/sso"):
            error.append(f"{was}: prefix without mount {destination!r}")


def _walkthrough(name: str, client: TestClient, auth, mails: list, prefix: str, base: str) -> None:
    """`base`: how the browser calls the pages (mount: with /sso; behind the proxy: also with /sso
    — the proxy strips it, the client sees the prefix). `client` talks to the app directly."""
    error: list = []
    redirects: list = []

    def get(path, **kw):
        a = client.get(path, follow_redirects=False, **kw)
        if a.status_code in (301, 302, 303, 307, 308):
            redirects.append((path, a.headers.get("location", "")))
        return a

    def post(path, **kw):
        a = client.post(path, follow_redirects=False, **kw)
        if a.status_code in (301, 302, 303, 307, 308):
            redirects.append((path, a.headers.get("location", "")))
        return a

    # Not signed in: protected page → login with next in the prefix.
    protected = get(f"{base}/app", headers=HTML)
    r.check(f"{name}: protected page → login in the prefix, next = path of the browser",
            protected.headers.get("location", "") == f"{prefix}/auth/login?next={prefix}/app",
            protected.headers.get("location", ""))
    for page_html in ("/auth/login", "/auth/register", "/auth/forgot", "/auth/magic/request",
                  f"/auth/login?next={prefix}/app"):
        _check_page_html(page_html, get(f"{base}{page_html}", headers=HTML), prefix, error)
    # Sign in: back to the protected page (next), then account and panel.
    post(f"{base}/auth/login", data={"username": "chefin", "password": PW, "next": f"{prefix}/app"})
    r.check(f"{name}: after the login back to the protected page",
            get(f"{base}/app").json() == {"u": "chefin"})
    for page_html in ("/auth/account", "/auth/admin", "/auth/totp/setup"):
        response = get(f"{base}{page_html}", headers=HTML)
        _check_page_html(page_html, response, prefix, error)
    # An account with TOTP: after the password the factor step follows — in the prefix.
    import pyotp
    uid_t = auth.create_user("zweifach", password=PW)
    secret_text = auth.totp_begin(uid_t)["secret"]
    import time as _t
    auth.totp_confirm(uid_t, pyotp.TOTP(secret_text).at(_t.time() - 30))
    step = TestClient(client.app).post(f"{base}/auth/login", follow_redirects=False,
                                          data={"username": "zweifach", "password": PW, "next": f"{prefix}/app"})
    r.check(f"{name}: the next factor step (TOTP) lies in the prefix",
            step.headers.get("location", "").startswith(f"{prefix}/auth/totp?next="),
            step.headers.get("location", ""))
    # Without next: the fallback login_redirect ("/") lies in the prefix.
    without_next = post(f"{base}/auth/login", data={"username": "chefin", "password": PW})
    r.check(f"{name}: without next the login leads to login_redirect in the prefix",
            without_next.headers.get("location", "") == f"{prefix}/", without_next.headers.get("location", ""))
    # Logout → logout_redirect in the prefix.
    out = post(f"{base}/auth/logout")
    r.check(f"{name}: logout leads to logout_redirect in the prefix",
            out.headers.get("location", "").startswith(f"{prefix}/auth/login"),
            out.headers.get("location", ""))
    # Sign-in link: confirmation page (form target) and redeeming.
    tok = auth.create_magic_token("login", user_id=auth.store.get_user_by_name("chefin")["id"])
    _check_page_html("magic-confirm", get(f"{base}/auth/magic/{tok}", headers=HTML), prefix, error)
    redeemed = post(f"{base}/auth/magic/{tok}")
    r.check(f"{name}: sign-in link redeemed → target in the prefix",
            redeemed.headers.get("location", "").startswith(f"{prefix}/"),
            redeemed.headers.get("location", ""))
    post(f"{base}/auth/logout")
    # Reset: the mail link carries the prefix exactly once (base_url), the page its targets.
    mails.clear()
    post(f"{base}/auth/forgot", data={"email": ""}, headers=HTML)
    auth.store.set_email(auth.store.get_user_by_name("chefin")["id"], "chefin@example.com", verified=True)
    post(f"{base}/auth/forgot", data={"email": "chefin@example.com"}, headers=HTML)
    links = [w for w in " ".join(mails).split() if w.startswith("http")]
    r.check(f"{name}: the reset link carries the prefix exactly once",
            len(links) == 1 and links[0].startswith(f"https://example.com{prefix}/auth/reset?")
            and links[0].count("/sso") == (1 if prefix else 0), str(links))
    if links:
        path_reset = links[0].split("example.com", 1)[1]
        path_reset = path_reset[len(prefix):] if prefix else path_reset
        _check_page_html("reset", get(f"{base}{path_reset}", headers=HTML), prefix, error)
    # Registration: after creation in the prefix.
    reg = post(f"{base}/auth/register", data={"username": "neu", "password": PW + "x",
                                                "email": "neu@example.com"})
    r.check(f"{name}: registration leads into the prefix",
            reg.headers.get("location", "").startswith(f"{prefix}/"), reg.headers.get("location", ""))

    outlier = [(p, z) for p, z in redirects
                  if z.startswith("/") and (not z.startswith(prefix + "/") if prefix else z.startswith("/sso"))]
    r.check(f"{name}: every redirect stays in the prefix ({len(redirects)} measured)",
            redirects and not outlier, str(outlier[:5]))
    r.check(f"{name}: every reference of the pages stays in the prefix, no placeholder",
            not error, "; ".join(error[:6]))


# ── Mount ────────────────────────────────────────────────────────────────────────────────
auth_m, app_m, mails_m = _setup("/sso")
outside = Starlette(routes=[Mount("/sso", app=app_m)])
_walkthrough("Mount /sso", TestClient(outside), auth_m, mails_m, "/sso", "/sso")

# ── uvicorn --root-path behind a proxy that strips /sso ───────────────────────────────────
auth_u, app_u, mails_u = _setup("/sso")
_walkthrough("uvicorn --root-path /sso", TestClient(_like_uvicorn(app_u, "/sso")), auth_u, mails_u, "/sso", "")

# ── Root: nothing changed ─────────────────────────────────────────────────────────────────
auth_w, app_w, mails_w = _setup("")
_walkthrough("Wurzel", TestClient(app_w), auth_w, mails_w, "", "")

# ── A root_path in an unexpected form is not carried into pages ───────────────────────────
# Without base_url (password only) the root_path of the request counts — here with markup in it.
cfg_x = TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                        csrf_enabled=False, passkey_enabled=False, lang="de")
auth_x = TinySesam(cfg_x)
app_x = FastAPI()
app_x.include_router(auth_x.router())
evil = TestClient(_like_uvicorn(app_x, "/sso'><script>x</script>"))
page_html_x = evil.get("/auth/login", headers=HTML)
r.check("a root_path with markup does not end up in the page (form checked, then empty)",
        page_html_x.status_code == 200 and "<form" in page_html_x.text
        and "x</script>" not in page_html_x.text and "sso'>" not in page_html_x.text
        and PREFIX_PLACEHOLDER not in page_html_x.text,
        f"HTTP {page_html_x.status_code} {page_html_x.text[:200]}")
ok_x = TestClient(_like_uvicorn(app_x, "/sso")).get("/auth/login", headers=HTML).text
r.check("… a valid root_path without base_url is carried by the page", "action='/sso/auth/login'" in ok_x)

# ── Counter-check T-15 ────────────────────────────────────────────────────────────────────
# G1: forward auth — the login URL in the header carries the prefix (with base_url, also for a
#     co-trusted target host that pulls the login page to itself).
cfg_f = TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                        csrf_enabled=False, passkey_enabled=False, forward_auth_enabled=True,
                        base_url="https://example.com/sso", trusted_redirect_hosts=["app.example.com"])
auth_f = TinySesam(cfg_f)
app_f = FastAPI()
app_f.include_router(auth_f.router())
c_f = TestClient(Starlette(routes=[Mount("/sso", app=app_f)]))
loc_f = c_f.get("/sso/auth/forward", headers={"x-forwarded-host": "example.com", "x-forwarded-proto": "https",
                                              "x-forwarded-uri": "/wiki/seite"}).headers.get("x-tinysesam-location", "")
loc_f2 = c_f.get("/sso/auth/forward", headers={"x-forwarded-host": "app.example.com", "x-forwarded-proto": "https",
                                               "x-forwarded-uri": "/wiki"}).headers.get("x-tinysesam-location", "")
r.check("G1: forward auth — login URL in the prefix, also on the co-trusted target host",
        loc_f.startswith("https://example.com/sso/auth/login?next=")
        and loc_f2.startswith("https://app.example.com/sso/auth/login?next="), f"{loc_f} | {loc_f2}")

# G2: guard of a host app OUTSIDE the TinySesam mount (host at the root, TinySesam under /sso).
auth_g, app_g, _ = _setup("/sso")
host = FastAPI()
host.mount("/sso", app_g)


@host.get("/dashboard")
def _dash(user=Depends(auth_g.require_user)):
    return {"u": user["username"]}


c_g = TestClient(host)
loc_g = c_g.get("/dashboard", headers=HTML, follow_redirects=False).headers.get("location", "")
form_g = REFERENCE.findall(c_g.get("/sso/auth/login", headers=HTML).text)
after_g = c_g.post("/sso/auth/login", data={"username": "chefin", "password": PW, "next": "/dashboard"},
                  follow_redirects=False).headers.get("location", "")
r.check("G2: guard of the host app → login in the prefix, next = path of the host app, back there",
        loc_g == "/sso/auth/login?next=/dashboard" and ("/sso/auth/login", "") in form_g
        and after_g == "/dashboard" and c_g.get("/dashboard").json() == {"u": "chefin"},
        f"{loc_g} | {after_g}")

# G3: a placeholder in data does not become a target; own templates stay byte-identical.
auth_p, app_p, _ = _setup("")
c_p = TestClient(app_p)
r.check("G3: safe_next rejects a target with the placeholder",
        auth_p.safe_next(f"/{PREFIX_PLACEHOLDER}/evil.example/x") == "/")
auth_p.set_template("login", lambda a, ctx: f"<a href='{ctx.get('next', '')}'>zurück</a> {PREFIX_PLACEHOLDER}")
own = c_p.get(f"/auth/login?next=/{PREFIX_PLACEHOLDER}/evil.example/x", headers=HTML).text
r.check("… and the output of an own template stays byte-identical (placeholder not replaced)",
        own == f"<a href='/'>zurück</a> {PREFIX_PLACEHOLDER}", own)

# G4: error page and sign-out confirmation stay in the prefix; render_panel is complete.
auth_e, app_e, _ = _setup("/sso")
auth_e.install_error_pages(app_e)
c_e = TestClient(Starlette(routes=[Mount("/sso", app=app_e)]))
error_e: list = []
_check_page_html("404", c_e.get("/sso/gibt-es-nicht", headers=HTML), "/sso", error_e)
_check_page_html("logout-rückfrage", c_e.get("/sso/auth/logout", headers={**HTML, "sec-fetch-site": "cross-site"}),
              "/sso", error_e)
from tinysesam.admin import render_panel  # noqa: E402
r.check("G4: error page and sign-out confirmation in the prefix; render_panel without placeholder",
        not error_e and PREFIX_PLACEHOLDER not in render_panel(auth_e, "/auth/admin")
        and 'href="/sso/auth/logout"' in render_panel(auth_e, "/sso/auth/admin", prefix="/sso"),
        "; ".join(error_e))

# G5: whoever still carries the prefix by hand in login_path gets a warning (otherwise /sso/sso/…).
from tinysesam import config_check as _kp  # noqa: E402
_warn = " ".join(_kp.check_config(TinySesamConfig(db_path=":memory:", base_url="https://example.com/sso",
                                           login_path="/sso/auth/login"))[1])
r.check("G5: login_path with the prefix of base_url → warning", "login_path='/sso/auth/login'" in _warn, _warn[:200])

# (Mutation probes: `render_page` does not replace the placeholder → “no placeholder” red;
#  `_prefix` without base_url path → G2 red; forward_login_url again with base+login_path → G1 red;
#  replacement also for own templates → G3 red; safe_next without placeholder check → G3 red;
#  `browser_path` returns the path unchanged → redirects red; `_prefix` without form check →
#  last check red; `safe_next` without request → “without next” red.)

sys.exit(r.done())
