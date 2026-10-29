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

PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/seite"}
PROBE_PASSWORD = "Probe-Pw-12345"


def brief(resp) -> str:
    """One line for a response: status and the parts of it that proxies and clients depend on.

    Values are recorded where they are the contract (`X-TinySesam-Reason`, `WWW-Authenticate`), only the path of
    redirect targets (`Location`, `X-TinySesam-Location`), only the names of identity headers and cookies —
    tokens and flow identifiers differ on every run."""
    teile = [str(resp.status_code)]
    namen = []
    for h in sorted(resp.headers.keys(), key=str.lower):
        kl = h.lower()
        wert = resp.headers[h]
        if kl == "www-authenticate":
            teile.append(f"WWW-Authenticate: {wert}")
        elif kl == "x-tinysesam-reason":
            teile.append(f"{canonical_header(h)}: {wert}")
        elif kl in ("location", "x-tinysesam-location"):
            teile.append(f"{canonical_header(h)} -> {urlsplit(wert).path or '/'}")
        elif kl.startswith(("x-tinysesam-", "remote-")):
            namen.append(canonical_header(h))
    if namen:
        teile.append("headers: " + ", ".join(sorted(namen)))
    cookies = []
    for c in resp.headers.get_list("set-cookie"):
        name = c.split("=", 1)[0]
        cookies.append(name + (" (cleared)" if "Max-Age=0" in c else ""))
    if cookies:
        teile.append("cookies: " + ", ".join(sorted(cookies)))
    return " | ".join(teile)


def probe_instance(**extra):
    from fastapi import FastAPI
    from tinysesam import TinySesam, TinySesamConfig
    werte = dict(db_path=os.path.join(tempfile.mkdtemp(prefix="tinysesam-probe-"), "f.db"),
                 base_url="https://auth.example.com", forward_auth_enabled=True, gate_token_enabled=True,
                 trusted_redirect_hosts=["app.example.com"], passkey_enabled=False, oidc_enabled=False,
                 csrf_enabled=False, https_mode="off", signup_require_email=False, apikey_enabled=True)
    werte.update(extra)
    cfg = TinySesamConfig(**werte)
    cfg.cookie_secure = False
    auth = TinySesam(cfg)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def sign_in(auth, app, create=False):
    from fastapi.testclient import TestClient
    if create:
        auth.create_user("anna", PROBE_PASSWORD, roles=["redaktion"])
    c = TestClient(app)
    c.post("/auth/login", data={"username": "anna", "password": PROBE_PASSWORD, "next": "/"},
           follow_redirects=False)
    return c


def _cookie_value(resp, name: str) -> str:
    return next(h.split(";")[0].split("=", 1)[1] for h in resp.headers.get_list("set-cookie")
                if h.startswith(name + "="))


def forward_scenarios() -> dict:
    """{scenario: one-line description of the response} — status codes, headers and cookies of the forward
    endpoint and the gate paths, observed on probe instances."""
    from fastapi.testclient import TestClient
    s = {}
    # --- forward auth in front of an application, gate token on (no central gateway) ---
    auth, app = probe_instance()
    anonym = TestClient(app)
    s["forward: not signed in"] = brief(anonym.get("/auth/forward", headers=PROXY))
    c = sign_in(auth, app, create=True)
    s["forward: signed in"] = brief(c.get("/auth/forward", headers=PROXY))
    s["verify alias: signed in"] = brief(c.get("/auth/verify", headers=PROXY))
    s["forward: role present (?roles=)"] = brief(c.get("/auth/forward?roles=chef,redaktion", headers=PROXY))
    s["forward: role missing (?roles=)"] = brief(c.get("/auth/forward?roles=chef", headers=PROXY))
    s["forward: role missing (X-TinySesam-Roles)"] = brief(
        c.get("/auth/forward", headers={**PROXY, "X-TinySesam-Roles": "chef"}))
    key = auth.create_api_key(auth.find_user("anna")["id"], name="probe")["key"]
    s["forward: API key"] = brief(TestClient(app).get("/auth/forward",
                                                      headers={**PROXY, "Authorization": f"Bearer {key}"}))
    s["gate logout: host not protected"] = brief(
        anonym.get("/.tinysesam/logout", headers={**PROXY, "X-Forwarded-Host": "other.example.org"}))
    s["gate logout: sign out everywhere"] = brief(
        sign_in(auth, app).get("/.tinysesam/logout?scope=all", headers=PROXY, follow_redirects=False))
    s["gate logout: sign out of this application only"] = brief(
        c.get("/.tinysesam/logout?scope=app", headers=PROXY, follow_redirects=False))
    s["forward: signed out of this application"] = brief(c.get("/auth/forward", headers=PROXY))
    # --- central gateway with code exchange (T-26) ---
    auth, app = probe_instance(gate_link_enabled=True)
    anonym = TestClient(app)
    s["gateway forward: not signed in"] = brief(anonym.get("/auth/forward", headers=PROXY))
    start = anonym.get("/.tinysesam/start?rd=/seite", headers=PROXY, follow_redirects=False)
    s["gateway start"] = brief(start)
    s["gateway start: host not protected"] = brief(
        anonym.get("/.tinysesam/start", headers={**PROXY, "X-Forwarded-Host": "other.example.org"}))
    s["gateway callback: unknown code"] = brief(anonym.get("/.tinysesam/callback?code=x", headers=PROXY))
    s["gateway authorize: unknown flow"] = brief(anonym.get("/auth/gate/authorize?flow=x"))
    s["gateway logout: host not protected"] = brief(anonym.get("/auth/gate/logout?host=other.example.org"))
    s["gateway logged-out page: host not protected"] = brief(
        anonym.get("/auth/gate/logged-out?host=other.example.org"))
    # the whole exchange: sign in on the gateway, authorize, redeem the code on the application's host
    c = sign_in(auth, app, create=True)
    flow = parse_qs(urlsplit(start.headers["location"]).query)["flow"][0]
    a = c.get(f"/auth/gate/authorize?flow={flow}", follow_redirects=False)
    s["gateway authorize: signed in"] = brief(a)
    code = parse_qs(urlsplit(a.headers["location"]).query)["code"][0]
    cb = TestClient(app).get(f"/.tinysesam/callback?code={code}", follow_redirects=False, headers={
        **PROXY, "Cookie": f"{auth._GATE_LINKFLOW_COOKIE}={_cookie_value(start, auth._GATE_LINKFLOW_COOKIE)}"})
    s["gateway callback: valid code"] = brief(cb)
    s["gateway forward: signed in via the connection"] = brief(TestClient(app).get(
        "/auth/forward", headers={**PROXY, "Cookie": f"{auth._GATE_LINK_COOKIE}="
                                                    f"{_cookie_value(cb, auth._GATE_LINK_COOKIE)}"}))
    return s


def hook_contract() -> str:
    """How `on_security_event` is called, observed: arguments, synchronous or not, before or after the change
    is written, and whether a failing hook aborts the operation."""
    import threading
    from tinysesam import TinySesam, TinySesamConfig
    cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(prefix="tinysesam-hook-"), "h.db"),
                          passkey_enabled=False, oidc_enabled=False)
    cfg.cookie_secure = False
    auth = TinySesam(cfg)
    uid = auth.create_user("hookprobe", PROBE_PASSWORD)
    gesehen = []

    def hook(ereignis, konto, details):
        gesehen.append({"args": (type(ereignis).__name__, type(konto).__name__, type(details).__name__),
                        "konto": sorted(konto), "thread": threading.get_ident(),
                        "neu_geschrieben": auth.store.get_user(uid)["username"] == "hookprobe2"})
    auth.on_security_event = hook
    auth.change_username(uid, "hookprobe2")
    bevor = len(gesehen)
    if not gesehen:
        return "the hook was not called"
    g = gesehen[0]

    def kaputt(ereignis, konto, details):
        raise RuntimeError("probe: a failing hook")
    auth.on_security_event = kaputt
    try:
        auth.change_username(uid, "hookprobe3")
        abgebrochen = False
    except RuntimeError:
        abgebrochen = True
    geaendert = auth.store.get_user(uid)["username"] == "hookprobe3"
    return (f"hook({', '.join(g['args'])}); account keys: {', '.join(g['konto'])}; "
            f"called {'synchronously' if g['thread'] == threading.get_ident() else 'in another thread'} "
            f"({bevor} call per change); {'after' if g['neu_geschrieben'] else 'before'} the change is written; "
            f"a failing hook {'aborts' if abgebrochen else 'does not abort'} the operation "
            f"(change {'written' if geaendert else 'lost'})")


def cfg_attribute() -> str:
    """What `auth.cfg` is: the instance passed to the constructor, a plain mutable dataclass."""
    from tinysesam import TinySesam, TinySesamConfig
    cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(prefix="tinysesam-cfg-"), "c.db"),
                          passkey_enabled=False, oidc_enabled=False)
    cfg.cookie_secure = False
    auth = TinySesam(cfg)
    params = TinySesamConfig.__dataclass_params__
    return (f"{type(auth.cfg).__name__}; the instance passed to the constructor: {auth.cfg is cfg}; "
            f"frozen: {params.frozen}")
