"""T-105 acceptance in a real browser: example Ex4, surface "headless" — a single-page application behind the server.

The stack of deploy/ex4 in one process: the server built from deploy/ex4/tinysesam.toml (host names moved to
example.test, which Chrome resolves to 127.0.0.1), the Node program of clients/js/examples/ex4, and in front the
forward-auth proxy of `_browser_stack` — here one that also keeps every request it hands to the application, so the
suite can show that no secret ever reached it.

  X1 a local account signs in through TinySesam's page and lands on the application's settings page, drawn in the
     browser from /.tinysesam/account.json; the application's pages have no password field.
  X2 at 375 and 1280 px, light and dark: a link of the settings page opens TinySesam's action page in the application's
     frame (name, icon, heading, ‹ Documents), never framed itself; "Back to Documents" returns with
     ts_result=cancelled, the settings page shows it and clears the address. Strict CSP everywhere, no console error,
     no broken request, no sideways scrolling, tap targets ≥ 44 px.
  X3 every write goes over an action page and back with done: the password (changed on TinySesam's page, the new one
     signs in), an API key (shown once in TinySesam's dialog), one other session ended by its handle (with the
     confirmation dialog), a connected program disconnected (the form sent by script, the page reloads as done).
  X4 a result the settings page did not ask for (a forged `state`) is ignored.
  X5 no secret in the application: the password, the new password, the API key and the sign-in link are in no
     request the application received and nowhere on its pages or in their storage.
  X6 administration (T-147): an administrator with the application's permission docs.admin drives every admin action
     on another account from the application's own links — roles, authenticator reset, key, program, one session, a
     sign-in link shown once, lock, unlock — each confirmed with the password on TinySesam's page, back with done.

Skipped without Chrome, `websockets` or `uvicorn`; needs `node` ≥ 22.18 (CI installs it in the jobs that run this suite).
`TINYSESAM_SCREENSHOTS=<dir>` keeps a screenshot of every state.
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from voraussetzung import braucht, braucht_modul, find_chrome, pflicht_werkzeug  # noqa: E402

braucht_modul("websockets")
braucht_modul("uvicorn")
CHROME = find_chrome()
braucht(CHROME, "no Chrome found")

import websockets  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from _browser_stack import SIZES, ForwardProxy, clean, free_port, serve, shot, view  # noqa: E402
from _cdp import Chrome, Page  # noqa: E402

PW = "a long probe password 4711"
NEW_PW = "another long probe password 0815"
NODE = pflicht_werkzeug("node", "example Ex4 (Node) behind the proxy")


def ok(name):
    print(f"  ✓ {name}", flush=True)


class RecordingProxy(ForwardProxy):
    """The proxy of `_browser_stack`, keeping every request it hands to the application (target, headers, body)."""

    seen: list = []

    async def _upstream(self, port, method, target, headers, body):  # type: ignore[override]
        if port == self.app_port:
            self.seen.append(f"{method} {target}\n" + "\n".join(f"{k}: {v}" for k, v in headers) + "\n"
                             + body.decode("latin-1"))
        return await ForwardProxy._upstream(port, method, target, headers, body)


if NODE:
    _version = subprocess.run([NODE, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
    _major, _minor = (int(x) for x in _version.lstrip("v").split(".")[:2])
    assert (_major, _minor) >= (22, 18), f"Ex4 needs Node >= 22.18 (type stripping), found {_version}"

    proxy = RecordingProxy(0, 0, auth_name="auth.example.test", app_name="app.example.test")
    AUTH, EX4 = f"http://auth.example.test:{proxy.port}", f"http://app.example.test:{proxy.port}"
    _tmp = tempfile.mkdtemp(prefix="ex4-")
    toml = (ROOT / "deploy" / "ex4" / "tinysesam.toml").read_text(encoding="utf-8")
    toml = (toml.replace("https://auth.example.com", AUTH).replace("example.com", "example.test")
            .replace('trusted_proxies = ["172.31.0.0/16"]', 'trusted_proxies = ["127.0.0.1/32"]')
            .replace('https_mode = "warn"', 'https_mode = "warn"\ncookie_secure = false\n'
                                            'cookie_domain = ".example.test"'))
    assert "example.com" not in toml and "cookie_domain" in toml, "deploy/ex4/tinysesam.toml changed its shape"
    with open(os.path.join(_tmp, "tinysesam.toml"), "w", encoding="utf-8") as fh:
        fh.write(toml)
    _saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("TINYSESAM_")}
    os.environ.update(TINYSESAM_CONFIG=os.path.join(_tmp, "tinysesam.toml"), TINYSESAM_DB=os.path.join(_tmp, "ex4.db"))
    try:
        from tinysesam import gateway
        ex4_app = gateway.build_app()
    finally:
        for _k in ("TINYSESAM_CONFIG", "TINYSESAM_DB"):
            os.environ.pop(_k, None)
        os.environ.update(_saved)
    auth = ex4_app.state.auth
    ICON = auth.cfg.apps["docs"]["icon"]
    TS_PORT, ts_server = serve(ex4_app)
    LOU = int(auth.create_user("lou", password=PW, roles=["docs-reader"]))
    auth.grant_permission("docs-reader", "docs.read", app="docs", by="test")

    APP_PORT = free_port()
    _node_log = open(os.path.join(_tmp, "ex4.log"), "w", encoding="utf-8")
    node_proc = subprocess.Popen([NODE, "examples/ex4/main.ts"], cwd=ROOT / "clients" / "js",
                                 env={**os.environ, "TS_LISTEN": f"127.0.0.1:{APP_PORT}"},
                                 stdout=_node_log, stderr=subprocess.STDOUT)
    import socket
    for _ in range(200):
        if node_proc.poll() is not None:
            raise RuntimeError(f"ex4 ended at start (exit {node_proc.returncode})")
        try:
            socket.create_connection(("127.0.0.1", APP_PORT), timeout=1).close()
            break
        except OSError:
            time.sleep(0.1)       # not listening yet
    else:
        raise RuntimeError("ex4 does not listen")
    proxy.ts_port, proxy.app_port = TS_PORT, APP_PORT

SETTINGS = "document.getElementById('settings')&&document.getElementById('settings').dataset.loaded==='1'"
ACTION = "!!document.getElementById('ts_back')"
SECRETS: list = [PW, NEW_PW]


async def on_settings(p: Page) -> None:
    await p.until(f"location.origin==={json.dumps(EX4)}&&location.pathname==='/settings'&&{SETTINGS}",
                  "not back on the settings page")


async def to_action(p: Page, act: str, path: str) -> None:
    """Follow the settings page's own link (with return and state) to TinySesam's action page."""
    await p.js(f"window.__old=true;document.querySelector('a.act[data-act={json.dumps(act)[1:-1]}]').click();true")
    await p.until(f"window.__old===undefined&&document.readyState==='complete'&&location.origin==={json.dumps(AUTH)}"
                  f"&&location.pathname==={json.dumps(path)}&&{ACTION}", f"no action page {path}")
    q = await p.js("JSON.stringify(Object.fromEntries(new URLSearchParams(location.search)))")
    q = json.loads(q)
    assert q.get("app") == "app.example.test" and q.get("return") == f"{EX4}/settings" and len(q.get("state", "")) == 24, q


async def back_with(p: Page, result: str, action: str) -> None:
    state = await p.js("document.getElementById('ts_back').dataset.state")
    assert state == result, f"the way back says {state}, not {result}"
    href = await p.js("document.getElementById('ts_back').href")
    assert all(s not in href for s in SECRETS), "a secret in the way back"
    await p.js("window.__old=true;document.getElementById('ts_back').click();true")
    await p.until("window.__old===undefined&&document.readyState==='complete'", "the way back did not load")
    await on_settings(p)
    notice = json.loads(await p.js("JSON.stringify({...document.getElementById('notice').dataset,"
                                   "hidden:document.getElementById('notice').hidden,search:location.search})"))
    assert notice == {"result": result, "action": action, "hidden": False, "search": ""}, notice


async def admin_action(p: Page, name: str, *, roles: tuple = (), check=None) -> None:
    """One administration action on lou: the application's link, TinySesam's page (the account named, the
    confirmation typed there), the action done, back with done — and its effect in the database."""
    await to_action(p, f"{name}-lou", f"/auth/act/{name}")
    assert "lou" in await p.js("document.getElementById('act_target').textContent"), name
    for role in roles:
        await p.js(f"document.querySelector('input[name=roles][value={json.dumps(role)}]').checked=true;true")
    await p.js(f"document.querySelector('#actform input[name=password]').value={json.dumps(PW)};"
               "window.__old=true;document.getElementById('act_confirm').click();true")
    await p.until("window.__old===undefined&&document.readyState==='complete'&&!!document.getElementById('ts_back')"
                  "&&document.getElementById('ts_back').dataset.state==='done'", f"{name} was not done")
    if check is not None:
        assert check(), f"{name}: no effect"
    await back_with(p, "done", name)


async def part_admin(p: Page) -> None:
    ada = int(auth.create_user("ada", password=PW, roles=["docs-admin"]))
    auth.store.set_admin(ada, True)
    auth.grant_permission("docs-admin", "docs.admin", app="docs", by="test")
    auth.store.set_totp(LOU, "JBSWY3DPEHPK3PXP", confirmed=True)
    now = int(time.time())
    auth.store.oauth_create_grant("probe-code-admin", "probe-cli", LOU, "https://app.example.test/mcp", "mcp", now,
                                  "192.0.2.1", now + 3600, [("probe-token-hash-2", "refresh", "mcp", now + 3600)])
    auth.start_session(LOU, "password", ua="Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")
    await p.go("about:blank")
    await p.cmd("Network.clearBrowserCookies")
    await p.go(EX4 + "/settings", "!!document.querySelector('input[name=username]')")
    await p.js(f"document.querySelector('input[name=username]').value='ada';"
               f"document.querySelector('input[name=password]').value={json.dumps(PW)};"
               "window.__old=true;document.querySelector('input[name=password]').form.requestSubmit();true")
    await p.until("window.__old===undefined&&document.readyState==='complete'", "ada's sign-in did not finish")
    await on_settings(p)
    assert await p.js(f"!!document.getElementById('admin-{LOU}')"), "no administration row for lou"
    assert await p.js("document.querySelectorAll('input[type=password],form').length") == 0, "a form in the app"
    user = lambda: auth.store.get_user(LOU)  # noqa: E731
    await admin_action(p, "admin_roles", roles=("docs-admin",),
                       check=lambda: sorted(auth.user_roles(user())) == ["docs-admin", "docs-reader"])
    await admin_action(p, "admin_totp_reset", check=lambda: not auth.store.has_confirmed_totp(LOU))
    await admin_action(p, "admin_key_revoke", check=lambda: all(k["revoked"] for k in auth.list_api_keys(LOU)))
    await admin_action(p, "admin_program_revoke", check=lambda: not auth._oauth_server().devices(LOU))
    sessions = len(auth.store.list_sessions(LOU))
    await admin_action(p, "admin_session_end", check=lambda: len(auth.store.list_sessions(LOU)) == sessions - 1)
    await to_action(p, "admin_signin_link-lou", "/auth/act/admin_signin_link")
    await p.js(f"document.querySelector('#actform input[name=password]').value={json.dumps(PW)};"
               "window.__old=true;document.getElementById('act_confirm').click();true")
    await p.until("window.__old===undefined&&document.readyState==='complete'&&!!document.getElementById('act_link')",
                  "no sign-in link shown")
    link = await p.js("document.getElementById('act_link').textContent")
    assert link.startswith(f"{AUTH}/auth/magic/"), link
    SECRETS.append(link)
    await back_with(p, "done", "admin_signin_link")
    await admin_action(p, "admin_lock", check=lambda: user()["disabled"] == 2)
    await admin_action(p, "admin_unlock", check=lambda: not user()["disabled"])
    assert [a["detail"].split()[0] for a in auth.store.recent_audit(50) if a["event"] == "admin_action"][::-1] == [
        f"act={n}" for n in ("admin_roles", "admin_totp_reset", "admin_key_revoke", "admin_program_revoke",
                             "admin_session_end", "admin_signin_link", "admin_lock", "admin_unlock")]
    ok("X6 administration: an administrator drives every admin action on another account from the application's "
       "own links — roles, authenticator reset, key, program, one session, a sign-in link shown once, lock, unlock — "
       "each confirmed with the password on TinySesam's page and back with done; audited in that order")


async def part_x(p: Page) -> None:
    console_before, failed_before = len(p.console), len(p.failed)

    # X1 ─ the local account signs in through TinySesam's page and lands on the settings page.
    await p.go("about:blank")
    await p.cmd("Network.clearBrowserCookies")
    await p.go(EX4 + "/settings", "!!document.querySelector('input[name=username]')")
    assert (await p.js("location.href")).startswith(f"{AUTH}/auth/login"), await p.js("location.href")
    await p.js(f"document.querySelector('input[name=username]').value='lou';"
               f"document.querySelector('input[name=password]').value={json.dumps(PW)};"
               "window.__old=true;document.querySelector('input[name=password]').form.requestSubmit();true")
    await p.until("window.__old===undefined&&document.readyState==='complete'", "the sign-in did not finish")
    await on_settings(p)
    assert await p.js("document.querySelectorAll('input[type=password],form').length") == 0, "a form in the app"
    assert await p.js("document.querySelector('#row-username span').textContent") == "User name: lou"
    await clean(p, "Ex4 settings after the sign-in", console_before, failed_before)
    ok("X1 the local account signs in on TinySesam's page and lands on the application's settings page, drawn in the "
       "browser from account.json; no password field and no form in the application")

    # X2 ─ an action page in the application's frame and back, at both sizes, light and dark.
    for width, height in SIZES:
        for theme in ("light", "dark"):
            where = f"Ex4 {width}px {theme}"
            await view(p, width, height, theme)
            await p.go(EX4 + "/settings", SETTINGS)
            assert await p.js("document.documentElement.classList.contains('dark')") == (theme == "dark"), where
            small = await p.js("[...document.querySelectorAll('a.act,nav.nav a')].filter(e=>e.offsetHeight&&"
                               "e.getBoundingClientRect().height<44).length")
            assert small == 0, f"{where}: tap targets under 44 px on the settings page"
            await clean(p, f"{where}: the settings page", console_before, failed_before)
            await to_action(p, "password", "/auth/act/password")
            # The theme lives in each origin's own storage: set it on TinySesam's origin too, and load the page again.
            await view(p, width, height, theme)
            await p.go(await p.js("location.href"), ACTION)
            assert await p.js("document.documentElement.classList.contains('dark')") == (theme == "dark"), where
            assert await p.js("document.querySelector('header').className") == "tsbar tsframe", f"{where}: no frame"
            assert await p.js("document.querySelector('a.tsbar-back').getAttribute('aria-label')") == \
                "Back to Documents", where
            assert await p.js("document.querySelector('.area-app span').textContent") == "Documents", where
            assert await p.js("document.querySelector('h1').textContent") == "Password", where
            assert await p.js(f"[...document.querySelectorAll('img.app-icon')].every(i=>i.getAttribute('src')==="
                              f"{json.dumps(ICON)}&&i.naturalWidth>0)"), f"{where}: the icon"
            assert await p.js("document.getElementById('ts_back').textContent") == "Back to Documents", where
            assert await p.js("!!document.getElementById('pw_cur')&&!document.getElementById('key_name')"), where
            small = await p.js("[...document.querySelectorAll('#ts_back,.sec button,.tsbar-btn,.tsbar-item,"
                               ".tsbar-links a')].filter(e=>e.offsetHeight&&e.getBoundingClientRect().height<44)"
                               ".map(e=>e.id||e.className||e.tagName)")
            assert small == [], f"{where}: tap targets under 44 px on the action page: {small}"
            await clean(p, f"{where}: the action page", console_before, failed_before)
            await shot(p, f"headless-action-{width}-{theme}")
            await back_with(p, "cancelled", "password")
            assert "nothing changed" in await p.js("document.getElementById('notice').textContent"), where
            await clean(p, f"{where}: back on the settings page", console_before, failed_before)
            await shot(p, f"headless-settings-{width}-{theme}")
    ok("X2 at 375 and 1280 px, light and dark: the settings page's link opens TinySesam's action page in the "
       "application's frame (‹ Documents, the icon, the name above the heading); back with ts_result=cancelled, "
       "shown and cleared from the address; strict CSP, no console error, no broken request, tap targets ≥ 44 px")

    # X3 ─ writing: password, API key, one session, a connected program — each over its action page and back done.
    await view(p, 1280, 900, "light")
    await p.go(EX4 + "/settings", SETTINGS)
    await to_action(p, "password", "/auth/act/password")
    await p.js(f"document.getElementById('pw_cur').value={json.dumps(PW)};"
               f"document.getElementById('pw_new').value={json.dumps(NEW_PW)};"
               "document.querySelector('[data-act=changepw]').click();true")
    await p.until("document.getElementById('pw_msg').classList.contains('good')"
                  "&&document.getElementById('ts_back').dataset.state==='done'", "the password did not change")
    assert await p.js("document.getElementById('ts_back').textContent") == "Done — back to Documents"
    await back_with(p, "done", "password")
    check = TestClient(ex4_app, base_url=AUTH, follow_redirects=False)
    check.get("/auth/login")
    r = check.post("/auth/login", data={"username": "lou", "password": NEW_PW,
                                        "_csrf": check.cookies.get(auth.csrf_cookie_name)})
    assert r.status_code == 303, "the new password does not sign in"
    ok("X3 the password: changed on TinySesam's action page, back with done; the new one signs in")

    await to_action(p, "api_keys", "/auth/act/api_keys")
    await p.js("document.getElementById('key_name').value='ci';document.querySelector('[data-act=mkkey]').click();true")
    await p.until("!!document.querySelector('dialog.tsdlg[open] textarea')", "no dialog with the new API key")
    key = await p.js("document.querySelector('dialog.tsdlg[open] textarea').value")
    assert key.startswith("tsk_"), key
    SECRETS.append(key)
    await p.js("document.querySelector('dialog.tsdlg[open] .tsdlg-ok').click();true")
    await p.until("!document.querySelector('dialog.tsdlg')&&document.getElementById('ts_back').dataset.state==='done'",
                  "the key dialog did not close")
    await back_with(p, "done", "api_keys")
    assert await p.js("document.querySelector('#row-api_keys span').textContent") == "API keys: 1"
    ok("X3 an API key: created and shown once in TinySesam's dialog, back with done; the settings count it")

    auth.start_session(LOU, "password", ua="Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")
    await p.go(EX4 + "/settings", SETTINGS)
    sessions = len(auth.store.list_sessions(LOU))       # this browser, the probe sign-in above, the new one
    count = await p.js("document.querySelector('#row-sessions span').textContent")
    assert sessions == 3 and count == f"{sessions} session(s)", count
    other = await p.js("document.querySelector('a.act[data-act^=session-]').dataset.act")
    await to_action(p, other, "/auth/act/session_end")
    await p.js("document.querySelector('[data-act=endsess]').click();true")
    await p.until("!!document.querySelector('dialog.tsdlg[open]')", "no confirmation dialog")
    await p.js("document.querySelector('dialog.tsdlg[open] .tsdlg-ok').click();true")
    await p.until("document.getElementById('se_msg').classList.contains('good')"
                  "&&document.getElementById('ts_back').dataset.state==='done'", "the session did not end")
    await back_with(p, "done", "session_end")
    assert await p.js("document.querySelector('#row-sessions span').textContent") == f"{sessions - 1} session(s)"
    assert len(auth.store.list_sessions(LOU)) == sessions - 1
    ok("X3 one session: its own End link (the session handle) opens the action page, TinySesam's dialog confirms, back "
       "with done; the settings list one session less")

    now = int(time.time())
    auth.store.oauth_add_client("probe-cli", "Probe CLI", ["http://127.0.0.1/cb"], now, "192.0.2.1")
    auth.store.oauth_create_grant("probe-code", "probe-cli", LOU, "https://app.example.test/mcp", "mcp", now,
                                  "192.0.2.1", now + 3600, [("probe-token-hash", "refresh", "mcp", now + 3600)])
    await p.go(EX4 + "/settings", SETTINGS)
    assert await p.js("document.querySelector('#row-programs span').textContent") == "Connected programs: 1"
    await to_action(p, "programs", "/auth/act/programs")
    await p.js("window.__old=true;document.querySelector('form.devrevoke button').click();true")
    await p.until("window.__old===undefined&&document.readyState==='complete'&&!document.querySelector('form.devrevoke')"
                  "&&document.getElementById('ts_back').dataset.state==='done'", "the program was not disconnected")
    assert await p.js("location.pathname") == "/auth/act/programs", "the page left the action page"
    await back_with(p, "done", "programs")
    assert await p.js("document.querySelector('#row-programs span').textContent") == "Connected programs: 0"
    await clean(p, "Ex4 after the writes", console_before, failed_before)
    ok("X3 a connected program: disconnected on the action page (the form sent by script, the page reloads as done), "
       "back with done; the settings count none")

    # X4 ─ a result the page did not ask for.
    await p.go(EX4 + "/settings?ts_action=password&ts_result=done&state=forged0000000000000000", SETTINGS)
    assert await p.js("document.getElementById('notice').dataset.result") == "foreign"
    assert await p.js("location.search") == ""
    ok("X4 a result with a state the settings page did not issue is ignored")

    # X6 ─ administration (T-147): an administrator drives every admin action on lou from the application and back.
    await part_admin(p)
    await clean(p, "Ex4 after the administration", console_before, failed_before)

    # X5 ─ no secret in the application.
    assert proxy.seen, "the proxy saw no request to the application"
    leaked = [s for s in SECRETS if any(s in req for req in proxy.seen)]
    assert not leaked, "a secret reached the application"
    page_text = await p.js("document.documentElement.outerHTML+JSON.stringify(Object.assign({},sessionStorage))"
                           "+JSON.stringify(Object.assign({},localStorage))")
    assert not any(s in page_text for s in SECRETS), "a secret on the application's page or in its storage"
    assert not any("tinysesam_session" in req for req in proxy.seen), "TinySesam's session cookie reached the app"
    ok(f"X5 no secret in the application: the passwords, the API key and the sign-in link are in none of the "
       f"{len(proxy.seen)} requests the application received, nor on its page or in its storage; nor the session cookie")


async def main() -> None:
    chrome = Chrome(CHROME, ("--host-resolver-rules=MAP *.example.test 127.0.0.1",))
    try:
        async with websockets.connect(chrome.new_tab(), max_size=30_000_000) as ws:
            p = Page(ws)
            await p.start()
            await proxy.start()
            try:
                await part_x(p)
            finally:
                proxy.close()
    finally:
        chrome.close()


if NODE:
    try:
        asyncio.run(main())
        print("OK test_headless_browser")
    finally:
        node_proc.terminate()
        node_proc.wait(timeout=10)
        _node_log.close()
        ts_server.should_exit = True
        import shutil
        shutil.rmtree(_tmp, ignore_errors=True)
