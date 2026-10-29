"""Probes of the HTTP and hook contract — what is observed on a running probe instance.

The static half of the measurement is `tests/_contract.py`. This half runs real requests (in-process, no network,
no extras) against probe instances and records what a proxy or a hook consumer can see: status codes, the
contract headers and cookies of the forward endpoint and the gate paths, and the call contract of
`on_security_event`.
"""
import os
import tempfile
from urllib.parse import parse_qs, urlsplit

from _contract import canonical_header

PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/page"}
PROBE_PW = "Probe-Pw-12345"


def brief(resp) -> str:
    """One line for a response: status and the parts of it that proxies and clients depend on.

    Values are recorded where they are the contract (`X-TinySesam-Reason`, `WWW-Authenticate`), only the path of
    redirect targets (`Location`, `X-TinySesam-Location`), only the names of identity headers and cookies —
    tokens and flow identifiers differ on every run."""
    parts = [str(resp.status_code)]
    names = []
    for h in sorted(resp.headers.keys(), key=str.lower):
        kl = h.lower()
        value = resp.headers[h]
        if kl == "www-authenticate":
            parts.append(f"WWW-Authenticate: {value}")
        elif kl == "x-tinysesam-reason":
            parts.append(f"{canonical_header(h)}: {value}")
        elif kl in ("location", "x-tinysesam-location"):
            parts.append(f"{canonical_header(h)} -> {urlsplit(value).path or '/'}")
        elif kl.startswith(("x-tinysesam-", "remote-")):
            names.append(canonical_header(h))
    if names:
        parts.append("headers: " + ", ".join(sorted(names)))
    cookies = []
    for c in resp.headers.get_list("set-cookie"):
        name = c.split("=", 1)[0]
        cookies.append(name + (" (cleared)" if "Max-Age=0" in c else ""))
    if cookies:
        parts.append("cookies: " + ", ".join(sorted(cookies)))
    return " | ".join(parts)


def probe_instance(**extra):
    from fastapi import FastAPI
    from tinysesam import TinySesam, TinySesamConfig
    values = dict(db_path=os.path.join(tempfile.mkdtemp(prefix="tinysesam-probe-"), "f.db"),
                 base_url="https://auth.example.com", forward_auth_enabled=True, gate_token_enabled=True,
                 trusted_redirect_hosts=["app.example.com"], passkey_enabled=False, oidc_enabled=False,
                 csrf_enabled=False, https_mode="off", signup_require_email=False, apikey_enabled=True)
    values.update(extra)
    cfg = TinySesamConfig(**values)
    cfg.cookie_secure = False
    auth = TinySesam(cfg)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def sign_in(auth, app, create=False):
    from fastapi.testclient import TestClient
    if create:
        auth.create_user("anna", PROBE_PW, roles=["editors"])
    c = TestClient(app)
    c.post("/auth/login", data={"username": "anna", "password": PROBE_PW, "next": "/"},
           follow_redirects=False)
    return c


def _cookie_value(resp, name: str) -> str:
    return next(h.split(";")[0].split("=", 1)[1] for h in resp.headers.get_list("set-cookie")
                if h.startswith(name + "="))


def forward_scenarios() -> dict:
    """{scenario: one-line description of the response} — status codes, headers and cookies of the forward
    endpoint and the gate paths, observed on probe instances.

    A step that fails (a route gone, a cookie missing) is recorded as `ERROR <type>` instead of aborting the
    probe: the comparison then names the scenario that changed, with its tier, rather than a traceback."""
    from fastapi.testclient import TestClient
    s, z = {}, {}

    def step(name, fn):
        try:
            s[name] = fn()
        except Exception as e:                        # noqa: BLE001 — a failing step IS the finding
            s[name] = f"ERROR {type(e).__name__}"

    # --- forward auth in front of an application, gate token on (no central gateway) ---
    auth, app = probe_instance()
    anonymous = TestClient(app)
    step("forward: not signed in", lambda: brief(anonymous.get("/auth/forward", headers=PROXY)))
    c = sign_in(auth, app, create=True)
    step("forward: signed in", lambda: brief(c.get("/auth/forward", headers=PROXY)))
    step("verify alias: signed in", lambda: brief(c.get("/auth/verify", headers=PROXY)))
    step("forward: role present (?roles=)",
            lambda: brief(c.get("/auth/forward?roles=chief,editors", headers=PROXY)))
    step("forward: role missing (?roles=)", lambda: brief(c.get("/auth/forward?roles=chef", headers=PROXY)))
    step("forward: role missing (X-TinySesam-Roles)", lambda: brief(
        c.get("/auth/forward", headers={**PROXY, "X-TinySesam-Roles": "chef"})))
    key = auth.create_api_key(auth.find_user("anna")["id"], name="probe")["key"]
    step("forward: API key", lambda: brief(TestClient(app).get(
        "/auth/forward", headers={**PROXY, "Authorization": f"Bearer {key}"})))
    step("gate logout: host not protected", lambda: brief(
        anonymous.get("/.tinysesam/logout", headers={**PROXY, "X-Forwarded-Host": "other.example.org"})))
    step("gate logout: sign out everywhere", lambda: brief(
        sign_in(auth, app).get("/.tinysesam/logout?scope=all", headers=PROXY, follow_redirects=False)))
    step("gate logout: sign out of this application only", lambda: brief(
        c.get("/.tinysesam/logout?scope=app", headers=PROXY, follow_redirects=False)))
    step("forward: signed out of this application", lambda: brief(c.get("/auth/forward", headers=PROXY)))
    # --- central gateway with code exchange (T-26) ---
    auth, app = probe_instance(gate_link_enabled=True)
    anonymous = TestClient(app)
    step("gateway forward: not signed in", lambda: brief(anonymous.get("/auth/forward", headers=PROXY)))

    def start():
        z["start"] = anonymous.get("/.tinysesam/start?rd=/page", headers=PROXY, follow_redirects=False)
        return brief(z["start"])
    step("gateway start", start)
    step("gateway start: host not protected", lambda: brief(
        anonymous.get("/.tinysesam/start", headers={**PROXY, "X-Forwarded-Host": "other.example.org"})))
    step("gateway callback: unknown code", lambda: brief(anonymous.get("/.tinysesam/callback?code=x", headers=PROXY)))
    step("gateway authorize: unknown flow", lambda: brief(anonymous.get("/auth/gate/authorize?flow=x")))
    step("gateway logout: host not protected", lambda: brief(anonymous.get("/auth/gate/logout?host=other.example.org")))
    step("gateway logged-out page: host not protected", lambda: brief(
        anonymous.get("/auth/gate/logged-out?host=other.example.org")))
    # the whole exchange: sign in on the gateway, authorize, redeem the code on the application's host
    c = sign_in(auth, app, create=True)

    def authorize():
        flow = parse_qs(urlsplit(z["start"].headers["location"]).query)["flow"][0]
        z["authorize"] = c.get(f"/auth/gate/authorize?flow={flow}", follow_redirects=False)
        return brief(z["authorize"])
    step("gateway authorize: signed in", authorize)

    def callback():
        code = parse_qs(urlsplit(z["authorize"].headers["location"]).query)["code"][0]
        flow_cookie = _cookie_value(z["start"], auth._GATE_LINKFLOW_COOKIE)
        z["callback"] = TestClient(app).get(f"/.tinysesam/callback?code={code}", follow_redirects=False, headers={
            **PROXY, "Cookie": f"{auth._GATE_LINKFLOW_COOKIE}={flow_cookie}"})
        return brief(z["callback"])
    step("gateway callback: valid code", callback)
    step("gateway forward: signed in via the connection", lambda: brief(TestClient(app).get(
        "/auth/forward", headers={**PROXY, "Cookie": f"{auth._GATE_LINK_COOKIE}="
                                                    f"{_cookie_value(z['callback'], auth._GATE_LINK_COOKIE)}"})))
    return dict(sorted(s.items()))


def hook_contract() -> str:
    """How `on_security_event` is called, observed: arguments, synchronous or not, before or after the change
    is written, and whether a failing hook aborts the operation."""
    import threading
    from tinysesam import TinySesam, TinySesamConfig
    cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(prefix="tinysesam-hook-"), "h.db"),
                          passkey_enabled=False, oidc_enabled=False)
    cfg.cookie_secure = False
    auth = TinySesam(cfg)
    uid = auth.create_user("hookprobe", PROBE_PW)
    seen = []

    def hook(event, account, details):
        seen.append({"args": (type(event).__name__, type(account).__name__, type(details).__name__),
                        "account": sorted(account), "thread": threading.get_ident(),
                        "new_written": auth.store.get_user(uid)["username"] == "hookprobe2"})
    auth.on_security_event = hook
    auth.change_username(uid, "hookprobe2")
    before = len(seen)
    if not seen:
        return "the hook was not called"
    g = seen[0]

    def broken(event, account, details):
        raise RuntimeError("probe: a failing hook")
    auth.on_security_event = broken
    try:
        auth.change_username(uid, "hookprobe3")
        aborted = False
    except RuntimeError:
        aborted = True
    changed = auth.store.get_user(uid)["username"] == "hookprobe3"
    return (f"hook({', '.join(g['args'])}); account keys: {', '.join(g['account'])}; "
            f"called {'synchronously' if g['thread'] == threading.get_ident() else 'in another thread'} "
            f"({before} call per change); {'after' if g['new_written'] else 'before'} the change is written; "
            f"a failing hook {'aborts' if aborted else 'does not abort'} the operation "
            f"(change {'written' if changed else 'lost'})")


def cfg_attribute() -> str:
    """What `auth.cfg` is: the instance passed to the constructor, a plain mutable dataclass."""
    from tinysesam import TinySesam, TinySesamConfig
    cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(prefix="tinysesam-cfg-"), "c.db"),
                          passkey_enabled=False, oidc_enabled=False)
    cfg.cookie_secure = False
    auth = TinySesam(cfg)
    params = TinySesamConfig.__dataclass_params__
    if not hasattr(auth, "cfg"):
        return "attribute missing"
    return (f"{type(auth.cfg).__name__}; the instance passed to the constructor: {auth.cfg is cfg}; "
            f"frozen: {params.frozen}")
