"""Response hardening for ASVS L3 (T-52): COOP, CSP reporting to TinySesam itself, Clear-Site-Data on sign-out.

- `Cross-Origin-Opener-Policy: same-origin` on every HTML response while `csp='strict'` (ASVS 3.4.8) — not on
  JSON, not with an own policy or `csp='off'` (then the proxy or the app decides, as for X-Frame-Options).
- `csp_report=True`: the strict policy names `<prefix>/auth/csp-report` (`report-uri` + `report-to`), the pages
  carry `Reporting-Endpoints`, and the endpoint logs one line per report — without the query of the page (tokens),
  with only the origin of the blocked resource, throttled per IP and in total, size-capped (ASVS 3.4.7).
  Nothing goes to a third party; the policy stays as strict as before.
- `Clear-Site-Data: "cache"` on every sign-out (ASVS 14.3.1), nothing broader.
"""
import json
import logging
import os
import tempfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


PW = "a long test password 4711"


def make(**kw):
    kw.setdefault("csrf_enabled", False)
    a = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False,
                                  passkey_enabled=False, admin_enabled=True, **kw))
    app = FastAPI()
    app.include_router(a.router())
    a.install_error_pages(app)
    return a, TestClient(app, base_url="https://testserver")


class Lines(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


seclog = logging.getLogger("tinysesam.security")
caught = Lines()
seclog.addHandler(caught)


# ---------- COOP ----------
a, c = make()
login = c.get("/auth/login")
assert login.headers.get("cross-origin-opener-policy") == "same-origin", dict(login.headers)
missing = c.get("/no-such-page", headers={"Accept": "text/html"})
assert missing.status_code == 404 and missing.headers.get("cross-origin-opener-policy") == "same-origin"
me = c.get("/auth/me")
assert me.status_code == 401 and "cross-origin-opener-policy" not in me.headers, "COOP on JSON"
a.ensure_admin("chef", PW)
assert c.post("/auth/login", data={"username": "chef", "password": PW}, follow_redirects=False).status_code in (200, 303)
panel = c.get("/auth/admin")
assert panel.status_code == 200 and panel.headers.get("cross-origin-opener-policy") == "same-origin"
ok("COOP same-origin on HTML pages (login, error page, admin panel), not on JSON")

for csp in ("off", "default-src 'self'; script-src 'nonce-{nonce}'"):
    _, c2 = make(csp=csp)
    assert "cross-origin-opener-policy" not in c2.get("/auth/login").headers, csp
ok("own policy or csp='off': no COOP (the proxy/app decides, like X-Frame-Options)")


# ---------- Clear-Site-Data on sign-out ----------
r = c.get("/auth/logout", follow_redirects=False)
assert r.status_code == 303 and r.headers.get("clear-site-data") == '"cache"', dict(r.headers)
assert c.post("/auth/login", data={"username": "chef", "password": PW}, follow_redirects=False).status_code in (200, 303)
r = c.post("/auth/logout", follow_redirects=False)
assert r.headers.get("clear-site-data") == '"cache"'
assert "clear-site-data" not in c.get("/auth/login").headers
ok('sign-out (GET and POST) sends Clear-Site-Data: "cache" — and only there, nothing broader')


# ---------- CSP reporting: off by default ----------
csp_off = login.headers["content-security-policy"]
assert "report-uri" not in csp_off and "report-to" not in csp_off and "reporting-endpoints" not in login.headers
assert c.post("/auth/csp-report", content=b"{}", headers={"Content-Type": "application/csp-report"}).status_code == 404
ok("csp_report off (default): no report target in the policy, endpoint 404")


# ---------- CSP reporting on ----------
a, c = make(csp_report=True)
page = c.get("/auth/login")
policy = page.headers["content-security-policy"]
assert policy.endswith("; report-uri /auth/csp-report; report-to tinysesam-csp"), policy
assert page.headers["reporting-endpoints"] == 'tinysesam-csp="/auth/csp-report"'
assert "'unsafe-inline'" not in policy and "script-src 'nonce-" in policy and "default-src 'self'" in policy
assert "http" not in policy.split("report-uri", 1)[1], "report target outside the own origin"
a.ensure_admin("chef", PW)
c.post("/auth/login", data={"username": "chef", "password": PW}, follow_redirects=False)
panel = c.get("/auth/admin")
assert "report-uri /auth/csp-report" in panel.headers["content-security-policy"]
assert panel.headers["reporting-endpoints"] == 'tinysesam-csp="/auth/csp-report"'
ok("csp_report on: strict policy unchanged plus own report-uri/report-to; Reporting-Endpoints on pages and panel")

TOKEN = "SECRETTOKEN0123456789"
caught.lines.clear()
legacy = {"csp-report": {"document-uri": f"https://testserver/auth/reset?token={TOKEN}#frag",
                         "violated-directive": "script-src-elem", "effective-directive": "script-src-elem",
                         "blocked-uri": "https://evil.example.net/x.js?k=" + TOKEN, "disposition": "enforce"}}
r = c.post("/auth/csp-report", content=json.dumps(legacy), headers={"Content-Type": "application/csp-report"})
assert r.status_code == 204, r.status_code
modern = [{"type": "csp-violation", "url": "https://testserver/auth/login",
           "body": {"documentURL": "https://testserver/auth/login?next=/x", "effectiveDirective": "style-src-attr",
                    "blockedURL": "inline", "disposition": "report"}},
          {"type": "deprecation", "body": {"id": "x"}}]
r = c.post("/auth/csp-report", content=json.dumps(modern), headers={"Content-Type": "application/reports+json"})
assert r.status_code == 204
assert caught.lines == [
    " ".join(["CSP violation directive=script-src-elem page=/auth/reset blocked=https://evil.example.net",
              "disposition=enforce ip=testclient"]),
    "CSP violation directive=style-src-attr page=/auth/login blocked=inline disposition=report ip=testclient",
], caught.lines
assert not any(TOKEN in line for line in caught.lines)
ok("report (report-uri and Reporting API format): one line each, page path without query, only the origin blocked")

caught.lines.clear()
evil = {"csp-report": {"document-uri": "https://testserver/a\nCSP violation directive=x ip=203.0.113.9",
                       "effective-directive": "script-src\nfake", "blocked-uri": "javascript\n:alert(1)"}}
c.post("/auth/csp-report", content=json.dumps(evil), headers={"Content-Type": "application/csp-report"})
assert len(caught.lines) == 1 and "\n" not in caught.lines[0], caught.lines
assert caught.lines[0].count(" ip=") == 1 and caught.lines[0].count("directive=") == 1, caught.lines
assert caught.lines[0].endswith(" ip=testclient"), caught.lines
for body, kind, want in ((b"x" * 9000, "application/csp-report", 413), (b"{}", "text/plain", 415),
                         (b"not json", "application/csp-report", 204)):
    assert c.post("/auth/csp-report", content=body, headers={"Content-Type": kind}).status_code == want, (kind, want)
ok("foreign values cannot forge a line; body over 8 KiB 413, wrong type 415, garbage 204 without a line")

# Per IP: 10 a minute (the requests above count: 2 + 1 + 3 = 6 so far).
codes = [c.post("/auth/csp-report", content=b"{}", headers={"Content-Type": "application/csp-report"}).status_code
         for _ in range(6)]
assert codes == [204] * 4 + [429] * 2, codes
ok("per IP at most 10 reports a minute, then 429")

caught.lines.clear()
a, c = make(csp_report=True)
a._CSP_REPORT_PER_IP = 1000          # stands in for many senders: only the total cap may bite here
one = json.dumps(legacy)
codes = {c.post("/auth/csp-report", content=one, headers={"Content-Type": "application/csp-report"}).status_code
         for _ in range(70)}
csp_lines = [x for x in caught.lines if x.startswith("CSP violation")]
assert codes == {204} and len(csp_lines) == 60, (codes, len(csp_lines))
ok("the log takes at most 60 report lines a minute in total, however many addresses send")

a, c = make(csp_report=True, base_url="https://testserver/sso")
p = c.get("/auth/login")
assert "report-uri /sso/auth/csp-report;" in p.headers["content-security-policy"]
assert p.headers["reporting-endpoints"] == 'tinysesam-csp="/sso/auth/csp-report"'
ok("under a mount prefix the report target carries it")

_, c = make(csp_report=True, csp="default-src 'self'; script-src 'nonce-{nonce}'")
p = c.get("/auth/login")
assert "report" not in p.headers["content-security-policy"] and "reporting-endpoints" not in p.headers
assert c.post("/auth/csp-report", content=b"{}", headers={"Content-Type": "application/csp-report"}).status_code == 404
ok("own policy: csp_report does nothing (no target added, endpoint 404)")

print("test_response_hardening: all checks passed")
