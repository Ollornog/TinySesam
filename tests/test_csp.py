"""CSP: nonce-based Content-Security-Policy for the built-in pages.

Proves the library's promise: every built-in page (login/account/TOTP/error)
runs under a strict, nonce-based CSP — no 'unsafe-inline'. The associated
browser proof (Chrome blocks on a wrong nonce) is in test_browser.py.
"""
import re
import os
import tempfile
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


_TAG = re.compile(r'<(script|style)\b')


def _cfg(**kw):
    return TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), csrf_enabled=False,
                           cookie_secure=False, pin_enabled=True, apikey_enabled=True, **kw)


def _pages(auth):
    return {
        "login": auth.render_page("login", request=None, next="/"),
        # WITH `events`: the route always passes them, and exactly the section “Latest events”
        # carried a `style=` attribute that the strict CSP blocks. Without `events` it was missing here,
        # and the check below stayed green (integration finding 9).
        # (Mutation probe: in templates.py put back `<p class=msg style='margin:0 0 8px'>` → rot.)
        "account": auth.render_page("account", request=None,
                                    user={"username": "u", "display_name": "U", "id": 1},
                                    methods=["password", "pin", "passkey"],
                                    events=[{"ts": 1767225600, "event": "login", "ip": "198.51.100.7"},
                                            {"ts": 1767225700, "event": "apikey_create", "ip": None,
                                             "by_admin": True}]),
        "totp": auth.render_page("totp", request=None, next="/"),
        "error": auth.render_page("error", request=None, code=404, message="x"),
    }


def _nonce(resp):
    m = re.search(r"'nonce-([\w-]+)'", resp.headers.get("content-security-policy", ""))
    return m.group(1) if m else None


# 1) Default 'strict': header present, every <script>/<style> with nonce, no inline handler/style=
auth = TinySesam(_cfg())
for name, resp in _pages(auth).items():
    csp = resp.headers.get("content-security-policy", "")
    assert csp.startswith("default-src 'self'"), f"{name}: no strict CSP: {csp!r}"
    assert "'unsafe-inline'" not in csp, f"{name}: CSP contains unsafe-inline"
    n = _nonce(resp)
    assert n, f"{name}: no nonce in the CSP"
    body = resp.body.decode()
    tags = len(_TAG.findall(body))
    nonced = len(re.findall(rf'<(?:script|style) nonce="{re.escape(n)}"', body))
    assert tags and tags == nonced, f"{name}: {nonced}/{tags} script/style genonced"
    assert not re.search(r'\son(click|submit)=', body), f"{name}: inline handler remained"
    assert not re.search(r'\sstyle=', body), f"{name}: style= attribute remained"
    # Precondition: the section is really there — otherwise the line above checked nothing.
    assert name != "account" or "id=eventlist" in body, "account: „Letzte Ereignisse“ missing"
ok("strict: header + nonce on every <script>/<style>, no inline handlers/style=")

# 2) A fresh nonce per response
n1, n2 = _nonce(auth.render_page("login", request=None)), _nonce(auth.render_page("login", request=None))
assert n1 and n2 and n1 != n2, "nonce not fresh per response"
ok("Nonce fresh per response")

# 3) csp='off' → no header (e.g. when a proxy sets the CSP centrally)
assert not TinySesam(_cfg(csp="off")).render_page("login", request=None) \
    .headers.get("content-security-policy")
ok("csp='off' → no header")

# 4) Own policy: {nonce} is replaced, the rest 1:1
cust = TinySesam(_cfg(csp="default-src 'self'; script-src 'nonce-{nonce}' https://cdn.example"))
csp = cust.render_page("login", request=None).headers["content-security-policy"]
assert "{nonce}" not in csp and csp.split().count("https://cdn.example") == 1 and "nonce-" in csp, csp
ok("custom policy: {nonce} replaced, rest 1:1")

# 5) Invalid csp (not a string) → clear rejection at build time
try:
    TinySesam(_cfg(csp=123))
    assert False, "csp=123 should have failed"
except ValueError:
    ok("csp must be a string (build rejects)")

# 6) Real HTTP path: the header is on the GET /auth/login response
app = FastAPI()
app.include_router(auth.router())
r = TestClient(app).get("/auth/login")
assert r.headers.get("content-security-policy", "").startswith("default-src 'self'")
ok("HTTP GET /auth/login carries the CSP header")

# 7) B3-2: a typo in `csp` was an “own policy” without a directive — the browser discarded
#    the header, the pages ran without CSP, nobody noticed. Now the build fails.
from tinysesam.errors import ConfigError  # noqa: E402
for wrong in ("Strict", "stirct", "OFF", "scirpt-src 'none'", ";"):
    try:
        TinySesam(_cfg(csp=wrong))
        assert False, f"csp={wrong!r} should have failed"
    except ConfigError as e:
        assert "csp=" in str(e), str(e)
for good in ("strict", "off", "", "default-src 'self'; script-src 'nonce-{nonce}'",
            "Default-Src 'self'; upgrade-insecure-requests"):
    TinySesam(_cfg(csp=good))
ok("csp: typos without a known directive fail at build time, real policies do not")
# A3: an unknown directive NEXT TO known ones is skipped by the browser and the rest applied —
#     a previously effective existing policy must not fail because of it, but should appear in the log.
import logging  # noqa: E402
from tinysesam import config_check  # noqa: E402


class _Trap(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


_trap = _Trap()
logging.getLogger("tinysesam.security").addHandler(_trap)
for mixed in ("default-src 'self'; require-sri-for script",
                 "default-src 'self'; disown-opener", "default-src 'self'; scirpt-src 'none'"):
    _trap.lines.clear()
    _gm = TinySesam(_cfg(csp=mixed))
    assert config_check.csp_error(mixed) == "", mixed
    assert any("does not know" in z for z in _trap.lines), (mixed, _trap.lines)
    assert any("does not know" in b for b in _gm.cfg.validate()), _gm.cfg.validate()
logging.getLogger("tinysesam.security").removeHandler(_trap)
assert config_check.csp_warning("default-src 'self'; script-src 'none'") == ""
ok("csp: unknown directive next to known ones warns instead of preventing the start")
# … and also after the build: `validate()` reports a typo set afterwards.
_after = TinySesam(_cfg())
_after.cfg.csp = "stict"
assert any("csp=" in b for b in _after.cfg.validate()), _after.cfg.validate()
ok("csp: validate() reports the typo set afterwards")


# 8) R8-5, R4-08, R5-2: hardening headers on EVERY TinySesam response, not only the page —
#    and on no route of the host.
from fastapi.responses import PlainTextResponse  # noqa: E402


def _hardness_app(**kw):
    a = TinySesam(_cfg(admin_enabled=True, password_reset_enabled=True, smtp_host="smtp.example",
                       base_url="https://auth.example", **kw))
    ap = FastAPI()
    ap.include_router(a.router())
    a.install_error_pages(ap)

    @ap.get("/gast")
    def guest():
        return PlainTextResponse("x", headers={"Vary": "Accept-Encoding"})
    return a, ap


_a8, _app8 = _hardness_app()
_c8 = TestClient(_app8)
_HEAD = {"x-content-type-options": "nosniff", "referrer-policy": "same-origin",
         "cache-control": "no-store"}
# `/auth/admin` without a session: the guard RAISES — the response is built by the exception handler,
# bypassing the route class. With and without install_error_pages.
_app8b = FastAPI()
_app8b.include_router(_a8.router())
for cl, away, expected in ((_c8, "/auth/login", 200), (_c8, "/auth/me", 401),
                          (_c8, "/auth/reset?token=geheim", 400), (_c8, "/auth/admin", 401),
                          (_c8, "/auth/admin/api/users", 401),
                          (TestClient(_app8b), "/auth/admin/api/users", 401)):
    rr = cl.get(away, follow_redirects=False)
    assert rr.status_code == expected, (away, rr.status_code)
    for k, v in _HEAD.items():
        assert rr.headers.get(k) == v, (away, k, rr.headers.get(k))
    assert "Cookie" in rr.headers.get("vary", ""), (away, rr.headers.get("vary"))
ok("nosniff, Referrer-Policy, no-store, Vary: Cookie on page, JSON, token page, raised 401")
_g = _c8.get("/gast")
assert "x-content-type-options" not in _g.headers and "cache-control" not in _g.headers, _g.headers
assert _g.headers.get("vary") == "Accept-Encoding", _g.headers.get("vary")
ok("host routes stay untouched")
# The branded error page bypasses no TinySesam route — it carries them anyway.
_f = _c8.get("/gibtsnicht", headers={"accept": "text/html"})
assert _f.status_code == 404 and _f.headers.get("x-content-type-options") == "nosniff", _f.headers
ok("the error page from install_error_pages also carries the headers")
# An existing Vary is extended, not replaced.
_v = _a8._header_lines(PlainTextResponse("x", headers={"Vary": "Accept-Encoding"}))
assert _v.headers["vary"] == "Accept-Encoding, Cookie", _v.headers["vary"]
_v2 = _a8._header_lines(PlainTextResponse("x", headers={"Vary": "cookie"}))
assert _v2.headers["vary"] == "cookie", _v2.headers["vary"]
ok("Vary: existing values stay, Cookie is added exactly once")
# X-Frame-Options only with 'strict' — an own policy or 'off' decides itself.
assert _c8.get("/auth/login").headers.get("x-frame-options") == "SAMEORIGIN"
_, _app_off = _hardness_app(csp="off")
_ro = TestClient(_app_off).get("/auth/login")
assert "x-frame-options" not in _ro.headers and _ro.headers.get("x-content-type-options") == "nosniff"
ok("X-Frame-Options only with csp='strict'; the other headers also apply with 'off'")


# 9) R8-1: the admin panel runs under the same CSP as every other page — without inline
#    handlers and without style=, otherwise the policy would break its own buttons.
_a8.ensure_admin("chef", "geheim-12345")
_c8.post("/auth/login", data={"username": "chef", "password": "geheim-12345", "next": "/"},
         follow_redirects=False)
_p = _c8.get("/auth/admin")
assert _p.status_code == 200, _p.status_code
_pcsp = _p.headers.get("content-security-policy", "")
assert _pcsp.startswith("default-src 'self'") and "'unsafe-inline'" not in _pcsp, _pcsp
assert _p.headers.get("x-frame-options") == "SAMEORIGIN", _p.headers
_pn = _nonce(_p)
_pb = _p.text
_ptags = len(_TAG.findall(_pb))
assert _ptags and _ptags == len(re.findall(rf'<(?:script|style) nonce="{re.escape(_pn)}"', _pb)), \
    "panel: not every <script>/<style> carries the nonce"
assert not re.search(r"\son[a-z]+=", _pb), re.findall(r"\son[a-z]+=[^>]{0,40}", _pb)[:3]
assert not re.search(r"\sstyle=", _pb), re.findall(r"\sstyle=[^>]{0,40}", _pb)[:3]
ok("admin panel: CSP with nonce, X-Frame-Options, no inline handlers/style=")
_api = _c8.get("/auth/admin/api/users")
assert _api.status_code == 200 and _api.headers.get("cache-control") == "no-store", _api.headers
assert _api.headers.get("x-content-type-options") == "nosniff"
ok("admin JSON API carries nosniff and no-store")
# Also on a freely chosen prefix via `admin_router()`.
_app9 = FastAPI()
_app9.include_router(_a8.router())
_app9.include_router(_a8.admin_router(), prefix="/verwaltung")
_c9 = TestClient(_app9)
_c9.post("/auth/login", data={"username": "chef", "password": "geheim-12345", "next": "/"},
         follow_redirects=False)
_p9 = _c9.get("/verwaltung")
assert _p9.status_code == 200 and "nonce-" in _p9.headers.get("content-security-policy", ""), _p9.headers
assert _p9.headers.get("cache-control") == "no-store"
ok("admin_router() on its own prefix: the same CSP and the same headers")


# 10) A1: the headers land in `exc.headers` without rewriting its keys. A
#     host handler reads `exc.headers["Location"]` — lowercased it did not find the
#     redirect and built a 307 without target.
from fastapi import HTTPException as _HE  # noqa: E402
from starlette.exceptions import HTTPException as _SHE  # noqa: E402
from fastapi.responses import JSONResponse as _JR, RedirectResponse as _RR  # noqa: E402

_app10 = FastAPI()
_app10.include_router(_a8.router())


@_app10.exception_handler(_SHE)
async def _guest_handler(request, exc):
    if exc.headers and "Location" in exc.headers:
        return _RR(exc.headers["Location"], status_code=303)
    return _JR({"detail": exc.detail, "keys": sorted((exc.headers or {}).keys())},
               status_code=exc.status_code, headers=exc.headers)


_r10 = TestClient(_app10).get("/auth/admin", headers={"accept": "text/html"}, follow_redirects=False)
assert _r10.status_code == 303 and _r10.headers.get("location", "").startswith("/auth/login"), \
    (_r10.status_code, _r10.headers)
_e = _HE(403, "x", headers={"X-TinySesam-Reauth": "/auth/reauth", "Vary": "Accept"})
_a8._header_lines_error(_e)
assert _e.headers["X-TinySesam-Reauth"] == "/auth/reauth" and _e.headers["Vary"] == "Accept, Cookie", _e.headers
assert _e.headers["X-Content-Type-Options"] == "nosniff" and "vary" not in _e.headers, _e.headers
ok("raised HTTPException: keys in exc.headers keep their spelling")


# 11) A2: the 422 (returns the input) and the JSON 500 from install_error_pages also carry
#     the headers — and the 422 still comes from the handler that the app has for it.
from fastapi.exceptions import RequestValidationError as _RVE  # noqa: E402


def _check_head(rr, was):
    for k, v in _HEAD.items():
        assert rr.headers.get(k) == v, (was, k, rr.headers.get(k))
    assert "Cookie" in rr.headers.get("vary", ""), (was, rr.headers.get("vary"))


_r422 = _c8.post("/auth/apikeys/abc/revoke")
assert _r422.status_code == 422 and _r422.json()["detail"][0]["loc"][-1] == "key_id", _r422.text
_check_head(_r422, "422")
_app11 = FastAPI()
_app11.include_router(_a8.router())


@_app11.exception_handler(_RVE)
async def _own_422(request, exc):
    return _JR({"eigen": True}, status_code=400)


_c11 = TestClient(_app11)
_c11.cookies.update(_c8.cookies)
_r11 = _c11.post("/auth/apikeys/abc/revoke")
assert _r11.status_code == 400 and _r11.json() == {"eigen": True}, _r11.text
_check_head(_r11, "eigener 422-Handler")
ok("422: headers included, the app's handler still builds the response")
_orig_audit = _a8.store.recent_audit


def _broken(*a, **k):
    raise RuntimeError("broken")


_a8.store.recent_audit = _broken
try:
    _r500 = TestClient(_app8, raise_server_exceptions=False).get(
        "/auth/admin/api/audit", cookies=dict(_c8.cookies))
finally:
    _a8.store.recent_audit = _orig_audit
assert _r500.status_code == 500 and _r500.json() == {"detail": "internal server error"}, _r500.text
_check_head(_r500, "500 JSON")
ok("JSON 500 from install_error_pages carries the headers")

print("\ntest_csp: all checks green")
