"""What existing data must survive — and what must not happen.

The docs cross-check of 2026-09-21 found seven places where the docs said something different
from the code. Five of them were not typos but real defects; this suite pins
them down so they do not come back. The worst: raising the scrypt parameters in
0.18.0 would have locked out every account running without the `[argon2]` extra.
The upgrade steps of old files (schema 9 → 10, plain-text unlocks of 0.17) went with the schema baseline (T-111).

All checks work without extras.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI                                    # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

from tinysesam import TinySesam, TinySesamConfig               # noqa: E402
from tinysesam import passwords                                # noqa: E402
from tinysesam.errors import ConfigError                       # noqa: E402
from tinysesam.store import Store                              # noqa: E402
from _kit.report import Report                                 # noqa: E402

r = Report("Legacy data — what an upgrade must survive")


def fresh(**cfg) -> tuple[TinySesam, str]:
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    kw = dict(db_path=db, lang="de", passkey_enabled=False, oidc_enabled=False,
              cookie_secure=False)
    kw.update(cfg)
    return TinySesam(TinySesamConfig(**kw)), db


# ---------------------------------------------------------------- existing scrypt hashes
# Up to 0.17.0 the format was `scrypt$salt$dk` and it did NOT carry its parameters; hashing
# used n=2^15, r=8, p=1. 0.18.0 raised p to 3 — and `verify_password` recomputed every old
# hash with the new p. The result would have been "wrong password" for every account without `[argon2]`,
# without a single error message naming the reason.
def old_hash(pw: str) -> str:
    """Create a hash in the 0.17.0 format (p=1, without parameters in the string)."""
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32,
                        maxmem=132 * 1024 * 1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


inventory = old_hash("dummy123")
r.check("existing hash from 0.17.0 still verifies",
        passwords.verify_password("dummy123", inventory),
        "the parameter increase locks out all scrypt accounts")
r.check("… and a wrong password, on the other hand, does not",
        not passwords.verify_password("wrong", inventory))
r.check("existing hash counts as needing renewal",
        passwords.needs_rehash(inventory),
        "otherwise the account stays on the weaker parameters forever")

new = "scrypt$%d$%d$%d$%s$%s" % (
    passwords._SCRYPT["n"], passwords._SCRYPT["r"], passwords._SCRYPT["p"],
    base64.b64encode(b"0123456789abcdef").decode(),
    base64.b64encode(hashlib.scrypt(b"dummy123", salt=b"0123456789abcdef",
                                    **passwords._SCRYPT)).decode())
r.check("hash in today's format verifies", passwords.verify_password("dummy123", new))
if not passwords._ARGON:
    # Without argon2 hash_password itself produces scrypt — then the new format must come out
    # and must not immediately count as outdated again.
    own = passwords.hash_password("dummy123")
    r.check("self-generated hash carries its parameters", own.count("$") == 5, own[:24])
    r.check("… and does not count as needing renewal", not passwords.needs_rehash(own))
else:
    r.check("without argon2 a new hash carries 5 separators",
            passwords.hash_password.__module__ == "tinysesam.passwords")

# And the path that counts in operation: an account whose hash comes from 0.17.0 signs in.
auth, db = fresh()
uid = auth.create_user("existing", password="dummy123")
auth.store.set_password_hash(uid, inventory)
r.check("sign-in with a 0.17.0 hash succeeds", bool(auth._check_password("existing", "dummy123")),
        "the login path computes differently from verify_password")

# A hashed unlock survives a restart (nothing at start clears it out).
auth1, db1 = fresh(resource_locks_enabled=True)
auth1.store.add_resource_unlock("fresh-token", "file-8", 4102444800)
auth1.close()
s2 = Store(db1)
s2.session_peppers = auth1.store.session_peppers      # what `TinySesam` sets at startup (T-71)
r.check("hashed unlock survives a restart",
        s2.is_resource_unlocked("fresh-token", "file-8"),
        "the cleanup reaches too far")
s2.close()

# ---------------------------------------------------------------- audit --user
# The command filtered the latest rows afterwards instead of filtering in SQL: whoever searched in the
# incident case (brute-force wave) got "Keine Einträge zu 'X'." and exit 0, although they were there.
auth2, _ = fresh()
auth2.audit("login_ok", username="victim", detail="alt")
for i in range(300):
    auth2.audit("login_fail", username="noise", detail=str(i))
hit = auth2.store.recent_audit(30, username="victim")
r.check("audit --user finds entries behind 300 rows of noise", len(hit) == 1,
        f"{len(hit)} found")
r.check("… and filters independently of capitalisation",
        len(auth2.store.recent_audit(30, username="VICTIM")) == 1)
r.check("without a filter the latest rows still come back",
        len(auth2.store.recent_audit(5)) == 5)

# ---------------------------------------------------------------- seed_demo
# The docstring promised "only with demo_mode=True", the body did not check it: a direct call
# created `demoadmin` with a known password and is_admin=1 — able to sign in, without a warning in the log.
auth3, _ = fresh()
try:
    auth3._seed_demo()
    r.check("seed_demo() without demo_mode is rejected", False, "it went through")
except ConfigError:
    r.check("seed_demo() without demo_mode is rejected", True)
r.check("… and creates no admin account in the process",
        auth3.store.get_user_by_name("demoadmin") is None)

# ---------------------------------------------------------------- stepup_strict
# `stepup_methods` was only ever a wish: whoever had none of the named methods set up
# confirmed with whatever they had — including the password they had just signed in with.
# That is no step-up. The barrier exists now, the default remains the old way.
auth4, _ = fresh(stepup_methods=["totp"])
u4 = auth4.store.get_user(auth4.create_user("without_totp", password="pw123456"))
r.check("stepup_methods remains a wish by default",
        auth4.stepup_options(u4) == ["password"], f"{auth4.stepup_options(u4)}")
auth5, _ = fresh(stepup_methods=["totp"], stepup_strict=True)
u5 = auth5.store.get_user(auth5.create_user("without_totp", password="pw123456"))
r.check("stepup_strict=True lets nothing through that was not wished for",
        auth5.stepup_options(u5) == [], f"{auth5.stepup_options(u5)}")
auth6, _ = fresh(stepup_methods=[], stepup_strict=True)
u6 = auth6.store.get_user(auth6.create_user("normal", password="pw123456"))
r.check("stepup_strict without stepup_methods changes nothing",
        auth6.stepup_options(u6) == ["password"], f"{auth6.stepup_options(u6)}")

# ---------------------------------------------------------------- login_chain dead end
# `login_chain=["password","totp"]` permanently locked out every account WITHOUT TOTP set up:
# the correct password led to /auth/totp, which, lacking a secret, redirected back to the login
# page — and the setup page demanded a fully signed-in user, which cannot exist under
# this chain. Neither in nor to the setup.
auth7, _ = fresh(login_chain=["password", "totp"], csrf_enabled=False)
auth7.create_user("chain", password="pw123456")
app7 = FastAPI()
app7.include_router(auth7.router())
c7 = TestClient(app7, follow_redirects=False)
ant = c7.post("/auth/login", data={"username": "chain", "password": "pw123456"})
r.check("correct password leads to the second factor",
        ant.status_code == 303 and "/auth/totp" in ant.headers.get("location", ""),
        f"{ant.status_code} {ant.headers.get('location')}")
ant = c7.get("/auth/totp")
r.check("/auth/totp without a secret sends to SETUP, not back to the login",
        ant.status_code == 303 and "/auth/totp/setup" in ant.headers.get("location", ""),
        f"{ant.status_code} {ant.headers.get('location')} — dead end")
ant = c7.get("/auth/totp/setup")
r.check("the setup page is reachable in this state", ant.status_code == 200,
        f"{ant.status_code}")

# Without a chain the old behaviour remains: no setup without a full sign-in.
auth8, _ = fresh(csrf_enabled=False)
auth8.create_user("klassisch", password="pw123456")
app8 = FastAPI()
app8.include_router(auth8.router())
c8 = TestClient(app8, follow_redirects=False)
ant = c8.get("/auth/totp/setup")
r.check("without a session the setup page leads on to the login",
        ant.status_code == 303 and "/auth/login" in ant.headers.get("location", ""),
        f"{ant.status_code} {ant.headers.get('location')}")

# ---------------------------------------------------------------- B-1: admin panel and CSRF
# The panel rolled a new CSRF token on EVERY request. Whoever opened it in a second tab
# invalidated the open form in the first — 403 without explanation. What is checked is the
# RAW Set-Cookie header: `TestClient` keeps a cookie jar and would swallow a renewed setting
# of the same value.
auth9, _ = fresh(csrf_enabled=True, admin_enabled=True)
auth9.ensure_admin("chef", "pw123456")
app9 = FastAPI()
app9.include_router(auth9.router())
c9 = TestClient(app9)
c9.get("/auth/login")                       # only now sets the CSRF cookie
note = c9.post("/auth/login", data={"username": "chef", "password": "pw123456",
                                   "_csrf": c9.cookies.get(auth9.cfg.csrf_cookie, "")},
              follow_redirects=False)
# 303 = signed in. Without `follow_redirects=False` the client would follow `next` and
# report the 404 of the target page — this app has no "/".
r.check("precondition: the sign-in succeeds", note.status_code == 303, f"{note.status_code}")
first = c9.get(auth9.cfg.admin_path)
# Without this precondition the test below would check nothing: a 401 naturally sets no
# CSRF cookie either, and the suite would have stayed green without ever having seen the case.
r.check("precondition: the panel is reachable", first.status_code == 200, f"{first.status_code}")
r.check("precondition: the first request SETS a CSRF cookie",
        any(k.lower() == "set-cookie" and v.startswith(auth9.cfg.csrf_cookie + "=")
            for k, v in first.headers.items())
        or bool(c9.cookies.get(auth9.cfg.csrf_cookie)),
        "no cookie — then the check below measures nothing")
second = c9.get(auth9.cfg.admin_path)
assigned = [v for k, v in second.headers.items() if k.lower() == "set-cookie"
           and v.startswith(auth9.cfg.csrf_cookie + "=")]
r.check("a second panel request sets NO new CSRF cookie", not assigned,
        f"{assigned} — the form in the first tab is therefore dead")

# ---------------------------------------------------------------- proxy templates
# A remote header not set in the template is not omitted but the CLIENT's own is
# passed through. The templates must therefore cover FORWARD_HEADERS_DEFAULT completely.
def missing_header(file: str) -> list[str]:
    """Which remote headers does this template not name? (In a function so that the text is not
    in module scope — there only the comprehension would read it, and CodeQL does not count that as
    use: `py/unused-global-variable`.)"""
    text = (ROOT / file).read_text(encoding="utf-8").lower()
    return [h for h in TinySesam.FORWARD_HEADERS_DEFAULT.values() if h.lower() not in text]


# ------------------------------------- The [argon2] extra is missing after an upgrade (B6-8)
# New image without the extra, a venv set up anew: every sign-in against an argon2 hash
# failed as „wrong password" — for all existing accounts, without a single log line.
# Simulated without uninstalling the extra: `_ARGON` switched off for the duration of the check.
import logging  # noqa: E402

# An argon2id hash of `geheim123` with minimal parameters (test data only, no secret).
ARGON_HASH = "$argon2id$v=19$m=8,t=1,p=1$lwj6WKW+poScm3635SRZ9Q$GB7yXwpoOqfsI27pXnI9FDaNWilsn2lwG85zAqfypFo"


class _Trap(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


trap = _Trap()
logging.getLogger("tinysesam").addHandler(trap)
was_argon = passwords._ARGON
auth_a, db_a = fresh()
uid_a = auth_a.create_user("altkonto", password="whatever12345")
auth_a.store.set_password_hash(uid_a, ARGON_HASH)
auth_a.close()
passwords._ARGON = False
passwords._ARGON2_REPORTED["ja"] = False
try:
    auth_b, _ = fresh(db_path=db_a)
    on_start = [z for z in trap.lines if "[argon2]" in z]
    r.check("if [argon2] is missing, startup names the affected hashes along with the remedy",
            any("1 affected hashes" in z and "pip install" in z for z in on_start),
            f"{trap.lines} — all existing accounts locked, and nobody learns why")
    trap.lines.clear()
    r.check("sign-in keeps failing (an argon2 hash cannot be checked without argon2)",
            not auth_b._check_password("altkonto", "dummy123"))
    r.check("…but no longer silent: the failure writes a line",
            any("[argon2]" in z for z in trap.lines), f"{trap.lines}")
    trap.lines.clear()
    auth_b._check_password("altkonto", "dummy123")
    r.check("…and only once, not one per sign-in attempt",
            not any("[argon2]" in z for z in trap.lines), f"{trap.lines}")
finally:
    passwords._ARGON = was_argon
    logging.getLogger("tinysesam").removeHandler(trap)
trap2 = _Trap()
logging.getLogger("tinysesam").addHandler(trap2)
fresh(db_path=db_a)
logging.getLogger("tinysesam").removeHandler(trap2)
r.check("with [argon2] startup stays quiet (control, provided the extra is present)",
        not was_argon or not any("[argon2]" in z for z in trap2.lines), f"{trap2.lines}")


# The home-network template (T-37) and the quickstart (deploy/quickstart) carry a copy of the forward-auth block —
# measured the same way, so that a copy cannot drift from the original unnoticed.
CADDYFILES = ("deploy/forward-auth/Caddyfile", "deploy/forward-auth/Caddyfile.gate", "deploy/home-network/Caddyfile",
              "deploy/quickstart/Caddyfile")
for file in ("deploy/forward-auth/nginx.conf", *CADDYFILES):
    missing = missing_header(file)
    r.check(f"{file} sets all remote headers", not missing, f"missing: {missing}")


# NEW-1: Every sub-request to TinySesam sets X-Forwarded-For itself. If it does not, nginx passes
# the CLIENT's header through — and because nginx is in trusted_proxies, the requester determined
# the IP for rate limit, lock and fail2ban. Reproduced with nginx:alpine: without the line an
# `X-Forwarded-For: 6.6.6.6` sent along arrived at TinySesam, with it 127.0.0.1.
def unprotected_subrequests(file: str) -> list[str]:
    """The `location` blocks that pass on to TinySesam without setting X-Forwarded-For."""
    text = (ROOT / file).read_text(encoding="utf-8")
    absent = []
    for head, body in re.findall(r"location\s+([^{]+)\{(.*?)\n\s*\}", text, re.S):
        if "proxy_pass" in body and ":8000" in body:
            if not re.search(r"proxy_set_header\s+X-Forwarded-For\s+\$(remote_addr|proxy_add_x_forwarded_for)\s*;",
                             body):
                absent.append(head.strip())
    return absent


for file in ("deploy/forward-auth/nginx.conf", "deploy/forward-auth/nginx-path.conf"):
    r.check(f"{file}: every path to TinySesam sets X-Forwarded-For itself (NEW-1)",
            not unprotected_subrequests(file), f"without: {unprotected_subrequests(file)}")


# B-20: The session cookie does not go to the protected app. What is measured is the rule itself:
# the `header_up Cookie` lines of the template, applied in their order (Go RE2 and Python's
# `re` read these patterns the same way; reproduced against real Caddy 2.11).
def caddy_cookie_rules(file="deploy/forward-auth/Caddyfile") -> list[tuple[str, str]]:
    text = (ROOT / file).read_text(encoding="utf-8")
    return [(pattern.replace("\\\\", "\\"), replacement)
            for pattern, replacement in re.findall(r'^\s*header_up\s+Cookie\s+"((?:[^"\\]|\\.)*)"\s+"([^"]*)"',
                                             text, re.M)]


def cookie_to_caddy(cookie: str, file="deploy/forward-auth/Caddyfile") -> str:
    # The gate template carries the rules twice (fast path, return path); applied twice
    # they change nothing more — this also measures that they do not.
    for pattern, replacement in caddy_cookie_rules(file):
        cookie = re.sub(pattern, replacement, cookie)
    return cookie


_session = TinySesamConfig(db_path=":memory:").session_cookie
_cases = {
    f"a=1; {_session}=SECRET; b=2": "a=1; b=2",
    f"{_session}=SECRET; b=2": "b=2",
    f"a=1; {_session}=SECRET": "a=1",
    f"{_session}=SECRET": "",
    f"__Host-{_session}=SECRET; x=1": "x=1",
    f"{_session}=A; {_session}=B; c=3": "c=3",
    f"x{_session}=stays; y=2": f"x{_session}=stays; y=2",
    # A-5: the unlock and the CSRF cookie do not go to the app either.
    "a=1; tinysesam_runlock=R; __Secure-tinysesam_csrf=C; b=2": "a=1; b=2",
    ("tinysesam_oidc_flow=1; tinysesam_saml_flow=2; tinysesam_waflow=3; tinysesam_session=4; "
     "tinysesam_runlock=5; tinysesam_csrf=6; x=7"): "x=7",
    # The situation after the switch to `__Host-` (H-1): the old names remain in the browser until they
    # expire or TinySesam deletes them at the next sign-in, alongside the new ones — seven
    # tinysesam cookies. The six-stage nginx chain let the seventh (here the new session)
    # through to the app. (Mutation probe: the nginx chain at six stages without a latch → red.)
    ("tinysesam_session=ALT; tinysesam_csrf=A; tinysesam_runlock=A; __Host-tinysesam_csrf=c; "
     "__Host-tinysesam_runlock=r; __Host-tinysesam_waflow=w; __Host-tinysesam_session=NEW; a=1"): "a=1",
    ("a=1; tinysesam_session=ALT; tinysesam_csrf=A; tinysesam_runlock=A; __Host-tinysesam_csrf=c; "
     "__Host-tinysesam_runlock=r; __Host-tinysesam_waflow=w; b=2; __Host-tinysesam_session=NEW"): "a=1; b=2",
}
# The gate cookie (ADR-9) is also called tinysesam_* and falls under the same rule.
_cases["a=1; __Host-tinysesam_gate=eyJ.x.y; b=2"] = "a=1; b=2"
for file in CADDYFILES:
    r.check(f"{file}: the cookie rule in front of the app exists (B-20)", bool(caddy_cookie_rules(file)),
            "no header_up cookie line — the app receives the session cookie")
    _wrong = {one: cookie_to_caddy(one, file) for one, from_ in _cases.items()
               if cookie_to_caddy(one, file) != from_}
    r.check(f"{file}: the TinySesam cookies are removed, others stay untouched", not _wrong,
            f"{_wrong}")


# A-2: nginx likewise does not pass the TinySesam cookies on to the app (or to PHP). What is measured
# is the template's map chain itself, replayed in Python (PCRE and `re` read these patterns
# the same way; reproduced against real nginx 1.29 + php-fpm 8.3).
def nginx_app_cookie(file: str, cookie: str) -> str:
    text = (ROOT / file).read_text(encoding="utf-8")
    values = {"http_cookie": cookie}
    for source, destination, pattern, replacement, default in re.findall(
            r'^map \$(\w+) \$(\w+) \{ "~(.*?)" "(.*?)"; default \$(\w+); \}$', text, re.M):
        hit = re.match(pattern.replace("(?<", "(?P<"), values[source])
        values[destination] = (re.sub(r"\$(\w+)", lambda m: hit.group(m.group(1)) or "", replacement)
                       if hit else values[default])
    return values.get("ts_app_cookie", cookie)


for file in ("deploy/forward-auth/nginx.conf", "deploy/forward-auth/nginx-path.conf"):
    _n_wrong = {one: nginx_app_cookie(file, one) for one, from_ in _cases.items()
                if nginx_app_cookie(file, one) != from_}
    r.check(f"{file}: the TinySesam cookies are removed, others stay untouched (A-2)",
            not _n_wrong, f"{_n_wrong}")
    # How many tinysesam cookies a browser carries is not fixed: six names, each doubled in the
    # transition period after H-1 (old and `__Host-`), plus renamed cookies of several
    # instances. The chain must cover the transition situation completely, and anything beyond that
    # must never slip through to the app — better no cookie at all then (fail closed). Reproduced against real
    # nginx 1.31 (mainline at the time): 12 pieces → only the own ones, 13 → empty.
    # (Mutation probe: make the latch `$ts_ck_latch` ineffective → red from 13 cookies.)
    _tiers = len(re.findall(r'^map \$\w+ \$ts_ck\d+ ', (ROOT / file).read_text(encoding="utf-8"), re.M))
    r.check(f"{file}: the chain covers the transition situation (six names, old and __Host-)",
            _tiers >= 12, f"only {_tiers} Tiers")
    _through = {}
    for _n in range(0, 2 * _tiers + 3):
        _one = "; ".join([f"own{i}=v" for i in range(2)]
                         + [f"{'__Host-' if i % 2 else ''}tinysesam_x{i}=secret" for i in range(_n)]
                         + ["own9=v"])
        _out = nginx_app_cookie(file, _one)
        if "tinysesam_" in _out or (_n <= _tiers and _out != "own0=v; own1=v; own9=v"):
            _through[_n] = _out
    r.check(f"{file}: arbitrarily many tinysesam cookies — none reaches the app (fail closed)",
            not _through, f"{_through}")
_ngx = (ROOT / "deploy/forward-auth/nginx.conf").read_text(encoding="utf-8")
_ngx_app = _ngx.split("location / {")[1].split("proxy_pass")[0]
r.check("nginx.conf: the app gets the filtered cookie", "proxy_set_header Cookie $ts_app_cookie;" in _ngx_app)
_ngx_auth = _ngx.split("location = /auth/forward {")[1].split("}")[0]
r.check("nginx.conf: the sub-request to /auth/forward keeps the cookie",
        "proxy_set_header Cookie $http_cookie;" in _ngx_auth)
_path = (ROOT / "deploy/forward-auth/nginx-path.conf").read_text(encoding="utf-8")
r.check("nginx-path.conf: every PHP location gets the filtered cookie (also the open one)",
        _path.count("fastcgi_pass") == _path.count("fastcgi_param HTTP_COOKIE        $ts_app_cookie;"),
        "a fastcgi_pass location passes the cookie unfiltered to PHP")
_traefik = (ROOT / "deploy/forward-auth/traefik.yml").read_text(encoding="utf-8")
r.check("traefik.yml: the cookie gap is named and the way out is present (A-2)",
        "B-20" in _traefik and 'Cookie: ""' in _traefik)
for file in CADDYFILES:
    _text = (ROOT / file).read_text(encoding="utf-8")
    _auth_block = _text.split("rewrite /auth/forward")[1].split("handle_response @ok")[0]
    r.check(f"{file}: the sub-request to /auth/forward keeps the cookie (otherwise everyone is signed out)",
            "header_up Cookie" not in _auth_block)


# H-16: Caddy finds a response header in `{rp.header.…}` only in the spelling that Go's
# textproto makes of it (each word capitalised, the rest lower case). With `X-TinySesam-Location` a
# 302 with an EMPTY Location came out — without an error, without a log line.
def go_canonical(name: str) -> str:
    return "-".join(w[:1].upper() + w[1:].lower() for w in name.split("-"))


for file, extra in ((CADDYFILES[0], set()), (CADDYFILES[1], {"X-TinySesam-Gate-Cookie"}), (CADDYFILES[2], set()),
                    (CADDYFILES[3], set())):
    _placeholder = re.findall(r"\{rp\.header\.([A-Za-z0-9-]+)\}", (ROOT / file).read_text(encoding="utf-8"))
    _skewed = [p for p in _placeholder if p != go_canonical(p)]
    r.check(f"{file}: every {{rp.header.…}} placeholder is in Go-canonical form (H-16)",
            _placeholder and not _skewed, f"not canonical: {_skewed}")
    _sent = set(TinySesam.FORWARD_HEADERS_DEFAULT.values()) | {"X-TinySesam-Location"} | extra
    _missing = [h for h in _sent if go_canonical(h) not in _placeholder]
    r.check(f"{file}: every header TinySesam sends has its placeholder", not _missing,
            f"missing: {_missing}")

raise SystemExit(r.done())
