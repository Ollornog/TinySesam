"""`tinysesam diagnose` (T-79): a report the operator checks and sends themselves — never telemetry.

What is pinned here:
  * every configuration field is classified (`_diagnose.FIELDS`) — a new field without a class turns this red;
  * canaries: a unique value in every string, list and mapping field of the configuration, in the gateway's
    environment and in security log lines; none of them may appear in the report or in the link (raw or decoded).
    Self-probe: the raw `config_check` findings DO carry canaries, so the redaction had work to do;
  * no network: with every socket call forbidden, both entry points run through;
  * read-only: the database directory is byte-for-byte the same afterwards (no key created, nothing migrated);
  * the link: the bug form, URL-encoded, never longer than `LINK_MAX` — a long report leaves sections out and says so;
  * `.github/ISSUE_TEMPLATE/bug.yml` has a field for every section of the report and points to private reporting.

(Mutation probes, run by hand and listed in the CHANGELOG: `Redactor.text` returning its input -> the canary checks
turn red; the `key=value` redaction of log lines removed -> the log canary check turns red; one entry removed from
`FIELDS` -> the classification guard turns red.)
"""
import contextlib
import dataclasses
import hashlib
import io
import os
import re
import socket
import sys
import tempfile
from urllib.parse import unquote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinysesam import TinySesam, TinySesamConfig, _diagnose as D
from tinysesam.__main__ import main
from tinysesam import gateway

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY = "cnry"


def ok(name):
    print(f"  ✓ {name}")


def run(entry, argv):
    out = io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = entry(list(argv)) or 0
    except SystemExit as e:
        code = e.code or 0
    return code, out.getvalue()


def leaks(text: str) -> list[str]:
    """Every canary in a text — also inside the URL-encoded link."""
    found = set(re.findall(CANARY + r"\w*", text, re.IGNORECASE))
    found |= set(re.findall(CANARY + r"\w*", unquote(text), re.IGNORECASE))
    return sorted(found)


# --- 1. every field is classified --------------------------------------------------------------------------------------

def unclassified(cls) -> set:
    return {f.name for f in dataclasses.fields(cls)} ^ set(D.FIELDS)


assert unclassified(TinySesamConfig) == set(), \
    f"fields without a class in _diagnose.FIELDS (or classes without a field): {sorted(unclassified(TinySesamConfig))}"


@dataclasses.dataclass
class _Grown(TinySesamConfig):
    brand_new_field: str = ""


assert unclassified(_Grown) == {"brand_new_field"}, "self-probe: the guard must see a new field"
for name, cls in D.FIELDS.items():
    assert cls in (D.SHOW, D.REDACT, D.SECRET, D.METHODS) or isinstance(cls, frozenset), (name, cls)
# Secrets are SECRET, never a placeholder — the names that say so at least.
for name in ("smtp_password", "oidc_client_secret", "ldap_bind_password", "demo_password", "demo_pin",
             "saml_idp_x509cert", "redis_url"):
    assert D.FIELDS[name] == D.SECRET, name
ok("every configuration field is classified; a new one turns the guard red")


# --- 2. canaries in every field --------------------------------------------------------------------------------------

def canary_config(tmp: str) -> TinySesamConfig:
    cfg = TinySesamConfig()
    for i, f in enumerate(dataclasses.fields(TinySesamConfig)):
        c = f"{CANARY}{i:03d}q"
        value = getattr(cfg, f.name)
        if isinstance(value, bool) or isinstance(value, (int, float)):
            continue
        if f.name == "db_path":
            new = os.path.join(tmp, f"{c}.db")
        elif isinstance(value, str) or value is None or f.name in ("brand_header", "brand_footer"):
            if any(w in f.name for w in ("url", "issuer", "origin", "entity_id", "brand_icon")):
                new = f"https://{c}.example/{c}path?x={c}x"
            elif f.name in ("smtp_from", "smtp_user"):
                new = f"{c}@{c}mail.example"
            elif f.name in ("ldap_bind_dn", "ldap_user_base", "ldap_user_dn_template"):
                new = f"uid={c}u,ou={c}o,dc={c}d,dc=example"
            elif f.name.endswith("_file") or f.name == "security_log":
                new = os.path.join(tmp, f"{c}dir", f"{c}.txt")
            elif f.name in ("cookie_domain", "rp_id"):
                new = f".{c}.example"
            else:
                new = c
        elif isinstance(value, list):
            if f.name == "trusted_proxies":
                new = ["198.51.100.77/32", f"{c}net"]
            elif f.name == "admin_identifiers":
                new = [f"{c}@{c}.example", f"{c}user"]
            elif f.name == "trusted_redirect_hosts":
                new = [f"*.{c}.example", f"{c}b.example"]
            else:
                new = [c, f"{c}b"]
        elif isinstance(value, dict):
            if f.name == "oidc_clients":
                new = {f"{c}h.example": {"client_id": f"{c}id", "client_secret": f"{c}sec"}}
            elif f.name == "admin_delegates":
                new = {f"{c}lead": {"roles": [f"{c}role"], "manages": [f"{c}x"]}}
            elif f.name == "forward_apps":
                new = {f"{c}app.example": {"name": f"{c}name", "roles": [f"{c}r"]}}
            elif f.name == "forward_headers":
                new = {"user": f"X-{c}-User"}
            else:
                new = {f"{c}k": f"{c}v"}
        else:
            raise AssertionError(f"canary_config does not know the type of {f.name}: {type(value).__name__}")
        setattr(cfg, f.name, new)
    return cfg


tmp = tempfile.mkdtemp()
cfg = canary_config(tmp)
# Every string, list and mapping field carries a canary (self-probe of the generator).
for f in dataclasses.fields(TinySesamConfig):
    v = getattr(cfg, f.name)
    if not isinstance(v, (bool, int, float)):
        assert CANARY in repr(v), f"no canary in {f.name}"

# Self-probe: the raw findings carry canaries — the redaction is put to work, not tested on clean text.
_probe = TinySesamConfig(**{f.name: getattr(cfg, f.name) for f in dataclasses.fields(TinySesamConfig)})
_probe.lang = "en"
_errors, _warnings = _probe._findings()
assert any(CANARY in m for m in _errors + _warnings), "self-probe: config_check must echo canaries"

log = os.path.join(tmp, "security.log")
with open(log, "w", encoding="utf-8") as fh:
    fh.write(
        f"2026-11-21 10:00:00,001 WARNING login_failed user={CANARY}user1 ip=203.0.113.71 method=password reason=wrong_secret\n"
        f"2026-11-21 10:00:00,002 WARNING First admin granted via one-time token: {CANARY}admin2\n"
        f"2026-11-21 10:00:00,003 ERROR security_log /var/{CANARY}dir3/sec.log not writable (Permission denied: '/var/{CANARY}4')\n"
        f"2026-11-21 10:00:00,004 WARNING Admin flag withdrawn: user={CANARY}5, the identity provider no longer grants it\n"
        f"2026-11-21 10:00:00,005 WARNING csrf origin rejected sec-fetch-site=cross-site origin=https://{CANARY}6.example ip=2001:db8::{CANARY[:2]}77\n"
        f"2026-11-21 10:00:00,006 WARNING api key denied user={CANARY}7@{CANARY}8.example ip=198.51.100.9 reason=revoked\n"
        f"2026-11-21 10:00:00,007 WARNING deferred login user=\"{CANARY} nine\" ip=192.0.2.10 reason=pending\n"
        f"2026-11-21 10:00:00,008 WARNING X-Forwarded-For from 192.0.2.11 was already applied by the server: the client address arrives as the peer\n"
        f"2026-11-21 10:00:00,009 INFO login_ok user={CANARY}info\n"
    )
# The CLI loads a configuration from a module (below); the canary configuration goes straight into build_report.
report = D.build_report(cfg, mode="library", source="test", db_path=cfg.db_path, log_path=log, lines=50)
text = D.render(report)
url, _left = D.issue_link(report)
assert "## TinySesam diagnostics report" in text and "### Checks" in text
assert "config_check:" in text and "warning" in text, text
assert leaks(text) == [], f"canaries in the report: {leaks(text)}"
assert leaks(url) == [], f"canaries in the link: {leaks(url)}"
# The secrets show as `<set>`, nothing else.
assert "`oidc_client_secret` = <set>" in text and "`smtp_password` = <set>" in text, text
# The log section carries the warnings, not the INFO line, and keeps the code words.
assert "reason=wrong_secret" in text and "method=password" in text and "INFO" not in text.split("### Security log")[1]
assert "uvicorn applied X-Forwarded-For itself" in text, "the uvicorn hint from the log is missing"
ok("canaries in every field and in log lines: none in the report or the link")

# Through the CLI with a configuration module: the same, end to end.
mod = os.path.join(tmp, f"{CANARY}conf.py")
with open(mod, "w", encoding="utf-8") as fh:
    fh.write("from tinysesam import TinySesamConfig\n"
             f"config = TinySesamConfig(base_url='https://{CANARY}cli.example', oidc_client_secret='{CANARY}clisecret', "
             f"smtp_user='{CANARY}smtp@{CANARY}m.example', admin_identifiers=['{CANARY}boss'], "
             f"db_path={os.path.join(tmp, CANARY + 'cli.db')!r}, security_log={log!r})\n")
code, out = run(main, ["diagnose", "--config", f"{mod}:config"])
assert code == 0, out
assert "Source: a Python object (--config)" in out and "`base_url` = <url-" in out, out
assert "https://github.com/Ollornog/TinySesam/issues/new?template=bug.yml&" in out, out
assert leaks(out) == [], f"canaries in the CLI output: {leaks(out)}"
code, out = run(main, ["diagnose", "--config", f"{mod}:missing_name"])
assert code == 0 and "Could not be loaded: AttributeError" in out and leaks(out) == [], out
ok("CLI: --config module:attr, link at the end, no canary; a broken --config is reported by type")

# The gateway reads its environment.
_env = {
    "TINYSESAM_OIDC_ISSUER": f"https://{CANARY}gw.example/realms/{CANARY}realm",
    "TINYSESAM_OIDC_CLIENT_ID": f"{CANARY}gwid",
    "TINYSESAM_OIDC_CLIENT_SECRET": f"{CANARY}gwsecret",
    "TINYSESAM_BASE_URL": f"https://{CANARY}auth.example",
    "TINYSESAM_COOKIE_DOMAIN": f".{CANARY}dom.example",
    "TINYSESAM_PROTECTED_HOSTS": f"{CANARY}a.example,{CANARY}b.example",
    "TINYSESAM_TRUSTED_PROXIES": "198.51.100.0/24",
    "TINYSESAM_DB": os.path.join(tmp, f"{CANARY}gw.db"),
    "TINYSESAM_SECURITY_LOG": log,
}
_saved = {k: os.environ.get(k) for k in _env}
os.environ.update(_env)
try:
    code, out = run(gateway.main, ["diagnose"])
finally:
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
assert code == 0, out
assert "Mode: gateway" in out and "Source: environment of the gateway" in out and "mode=gateway" in out, out
assert "`oidc_client_secret` = <set>" in out, out
assert leaks(out) == [], f"canaries in the gateway output: {leaks(out)}"
ok("gateway: diagnose from the environment, no canary")


# --- 3. no network -----------------------------------------------------------------------------------------------------

class NetworkUsed(AssertionError):
    pass


def _forbidden(*_a, **_k):
    raise NetworkUsed("diagnose touched the network")


_orig = {name: getattr(socket, name) for name in ("create_connection", "getaddrinfo", "gethostbyname",
                                                  "gethostbyname_ex", "getfqdn")}
_orig_connect, _orig_connect_ex = socket.socket.connect, socket.socket.connect_ex
for name in _orig:
    setattr(socket, name, _forbidden)
socket.socket.connect = _forbidden          # type: ignore[method-assign]
socket.socket.connect_ex = _forbidden       # type: ignore[method-assign]
try:
    try:
        socket.create_connection(("192.0.2.1", 80))
        raise AssertionError("self-probe: the socket ban does not hold")
    except NetworkUsed:
        pass
    code, out = run(main, ["diagnose", "--config", f"{mod}:config", "--log", log])
    assert code == 0 and "### Security log" in out and "issues/new" in out, out
    os.environ.update(_env)
    try:
        code, out = run(gateway.main, ["diagnose"])
    finally:
        for k, v in _saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    assert code == 0 and "Mode: gateway" in out, out
finally:
    for name, fn in _orig.items():
        setattr(socket, name, fn)
    socket.socket.connect = _orig_connect          # type: ignore[method-assign]
    socket.socket.connect_ex = _orig_connect_ex    # type: ignore[method-assign]
ok("no network: with every socket call forbidden both entry points run through")


# --- 4. read-only on a real database -------------------------------------------------------------------------------------

work = tempfile.mkdtemp()
db = os.path.join(work, "auth.db")
auth = TinySesam(TinySesamConfig(db_path=db, cookie_secure=False, passkey_enabled=False))
auth.create_user("someone", password="a long probe password 4711")
auth.store.audit_log("login_ok", "someone", "192.0.2.1", "")
auth.close()      # a closed database: no -wal file, diagnose must not create one


def snapshot(folder: str) -> dict:
    out = {}
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        with open(path, "rb") as fh:
            out[name] = (hashlib.sha256(fh.read()).hexdigest(), os.stat(path).st_mtime_ns)
    return out


before = snapshot(work)
code, out = run(main, ["diagnose", "--db", db, "--no-link"])
assert code == 0, out
assert snapshot(work) == before, "diagnose wrote into the database directory"
assert "issues/new" not in out, "--no-link prints no link"
from tinysesam.store import Store
assert f"Database schema: {Store.SCHEMA_VERSION} (this version: {Store.SCHEMA_VERSION}) — current" in out, out
assert "Vault key: <db>.key, beside the database: yes" in out, out
assert "newest audit entry is not in the future (ok)" in out, out
assert "someone" not in out and "auth.db" not in out, out
# An empty directory stays empty: no database, no key created.
empty = tempfile.mkdtemp()
code, out = run(main, ["diagnose", "--db", os.path.join(empty, "none.db"), "--no-link"])
assert code == 0 and os.listdir(empty) == [] and "Database: not found" in out, out
ok("read-only: the database directory is unchanged, schema, vault key and clock reported")


# --- 5. the link -------------------------------------------------------------------------------------------------------

small = {k: f"short {k}" for k in D.SECTIONS}
url, left = D.issue_link(small, "gateway")
assert url.startswith(D.ISSUE_URL + "?template=bug.yml&") and left == [], url
assert "mode=gateway" in url and "environment=short%20environment" in url, url
big = dict(small, log="x" * 20000, checks="y" * 500)
url, left = D.issue_link(big)
assert len(url) <= D.LINK_MAX and left == ["log"], (len(url), left)
assert "too%20long%20for%20the%20link" in url and "y" * 500 in url, url
huge = {k: "z" * 20000 for k in D.SECTIONS}
url, left = D.issue_link(huge)
assert len(url) <= D.LINK_MAX and set(left) == set(D.SECTIONS), (len(url), left)
ok("link: bug form, URL-encoded, at most LINK_MAX; too long → sections left out and named")


# --- 6. the bug form -----------------------------------------------------------------------------------------------------

with open(os.path.join(ROOT, ".github", "ISSUE_TEMPLATE", "bug.yml"), encoding="utf-8") as fh:
    form = fh.read()
ids = set(re.findall(r"^\s+id:\s*([\w-]+)\s*$", form, re.M))
for needed in set(D.SECTIONS) | {"version", "mode"}:
    assert needed in ids, f"bug.yml lacks the field {needed!r} that the link fills"
assert "SECURITY.md" in form and "diagnose" in form, "bug.yml must point to private reporting and the command"
with open(os.path.join(ROOT, ".github", "ISSUE_TEMPLATE", "config.yml"), encoding="utf-8") as fh:
    contact = fh.read()
assert "security/advisories/new" in contact and "blank_issues_enabled" in contact, contact
ok("bug.yml: a field for every section of the report, private reporting named")


# --- 7. help -------------------------------------------------------------------------------------------------------------

code, out = run(main, ["--help"])
assert code == 0 and "diagnose" in out, out
code, out = run(gateway.main, ["--help"])
assert code == 0 and "diagnose" in out, out
ok("help of both entry points names diagnose")
