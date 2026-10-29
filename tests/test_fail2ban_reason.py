"""Every security-log line that a fail2ban filter reads carries its cause under `reason=` — never `grund=`.

T-29 moved the key vocabulary of audit details and log lines from German to English
(`grund=` -> `reason=`). The shipped filters in `deploy/fail2ban/` match `... method=\\S+(?: reason=\\S+)?$`:
a line that still said `grund=` would no longer match the optional group and — because of the `$`
anchor — would not be read by the jail at all. The ban would silently fall away, exactly on the
path that was missed.

Four things are measured here, each against the SHIPPED files and not against a copy of the pattern:

 (1) static: over `tinysesam/*.py`, every `seclog.<level>(...)` call whose line (format string
     with the event word substituted — `security.LOG_*`, `security.log_ereignis(...)`, a literal) contains one
     of the filter keywords uses a reason key only as `reason=`. The keywords are READ from the filters.
 (2) dynamic: real operations produce the lines (passkey, SSO with a locked account, API key, local
     and LDAP password, lockout, deferral) and the failregex loaded from the filter files hits them.
 (3) mutation: one place bent to `grund=` (in a copy of the source / in the running process) turns
     (1) and (2) red.
 (4) both filter regexes stay valid.

Parts that need an optional extra (`webauthn`, `authlib`) run only when it is installed and say so
aloud otherwise; the call sites are covered by (1) in any case.
"""
import ast
import importlib.util
import io
import itertools
import logging
import os
import re
import tempfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, security

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAKET = os.path.join(ROOT, "tinysesam")
FILTER_DIR = os.path.join(ROOT, "deploy", "fail2ban")
_FALSCH = itertools.count()      # always NEW wrong passwords: a repetition counts only once (password_repeat_memory)


def ok(name):
    print(f"  ✓ {name}")


def _lies(pfad):
    with open(pfad, encoding="utf-8") as fh:
        return fh.read()


def _extra_da(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Filters: failregex and keywords are READ from the shipped files
# ---------------------------------------------------------------------------
IP_MUSTER = r"(?P<host>(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+))"


def _failregex_roh(datei):
    """All `failregex` patterns of a filter file (the first line and indented continuation lines)."""
    muster, im_block = [], False
    for z in _lies(os.path.join(FILTER_DIR, datei)).splitlines():
        if z.startswith("failregex"):
            muster.append(z.split("=", 1)[1].strip())
            im_block = True
        elif im_block and z[:1] in (" ", "\t") and z.strip() and not z.strip().startswith("#"):
            muster.append(z.strip())
        else:
            im_block = False
    return [m for m in muster if m]


def _regexe(datei):
    roh = _failregex_roh(datei)
    assert roh, f"{datei}: no failregex found"
    return [re.compile(m.replace("<HOST>", IP_MUSTER)) for m in roh]


def _trifft(regexe, zeile):
    """The match of the first pattern that hits the line, else None."""
    for rx in regexe:
        m = rx.search(zeile)
        if m:
            return m
    return None


# (4) both regexes compile (and the loader finds exactly what the file declares)
JAIL = _regexe("tinysesam-filter.conf")
JAIL_PRUEFUNG = _regexe("tinysesam-verify-filter.conf")
for _datei in ("tinysesam-filter.conf", "tinysesam-verify-filter.conf"):
    assert all("<HOST>" in m for m in _failregex_roh(_datei)), _datei
ok("(4) both filter regexes compile and carry <HOST>")


def _stichworte():
    """Event words the filters talk about: `failed login`, `failed verification` (from the failregex)
    and `deferred login` (named in the comment as deliberately NOT matched)."""
    worte = set()
    for datei in sorted(os.listdir(FILTER_DIR)):
        if not datei.endswith("-filter.conf"):
            continue
        text = _lies(os.path.join(FILTER_DIR, datei))
        worte.update(re.findall(r"`((?:failed|deferred) [a-z]+)", text))
        for m in _failregex_roh(datei):
            worte.update(re.findall(r"WARNING ((?:failed|deferred) [a-z]+) ", m))
    return worte


STICHWORTE = _stichworte()
assert {"failed login", "failed verification"} <= STICHWORTE, STICHWORTE
assert any(w.startswith("deferred ") for w in STICHWORTE), f"no deferral word in the filters: {STICHWORTE}"
ok(f"filter keywords read from deploy/fail2ban: {sorted(STICHWORTE)}")


# ---------------------------------------------------------------------------
# (1) static analysis (AST)
# ---------------------------------------------------------------------------
# The reading of the call sites lives in `tests/_seclog_ast.py` (shared with `tests/test_api_surface.py`,
# which pins the line shapes the operator promise covers).
import sys  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _seclog_ast import EREIGNIS, formatvarianten as _formatvarianten, seclog_aufrufe as _seclog_aufrufe  # noqa: E402

assert EREIGNIS == {"failed login", "failed verification"}, EREIGNIS


_SCHLUESSEL = re.compile(r"\b([A-Za-z_]*(?:grund|reason|cause|why)[A-Za-z_]*)=", re.IGNORECASE)


def _pruefe_quelle(quelle, name):
    """-> (filter lines found, violations in them, violations in ANY seclog call)."""
    filterzeilen, in_filter, ueberall = [], [], []
    for a, lokal in _seclog_aufrufe(quelle):
        varianten = _formatvarianten(a, lokal)
        text = ast.unparse(a)
        schluessel = {s for v in varianten for s in _SCHLUESSEL.findall(v)}
        if "grund=" in text:
            ueberall.append(f"{name}:{a.lineno}: grund= in a security-log call")
        if any(w in v for v in varianten for w in STICHWORTE):
            filterzeilen.append((name, a.lineno))
            falsch = sorted(s for s in schluessel if s != "reason")
            if falsch or "grund=" in text:
                in_filter.append(f"{name}:{a.lineno}: filter line with the cause under {falsch or ['grund']}")
    return filterzeilen, in_filter, ueberall


alle_filterzeilen, alle_verstoesse, alle_ueberall = [], [], []
for datei in sorted(os.listdir(PAKET)):
    if datei.endswith(".py"):
        f, v, u = _pruefe_quelle(_lies(os.path.join(PAKET, datei)), datei)
        alle_filterzeilen += f
        alle_verstoesse += v
        alle_ueberall += u
dateien_mit_filterzeilen = {d for d, _ in alle_filterzeilen}
# Not vacuous: the places that are known to write filter lines must be FOUND by the analysis.
assert {"manager.py", "oidc.py", "webauthn_.py"} <= dateien_mit_filterzeilen, dateien_mit_filterzeilen
assert len(alle_filterzeilen) >= 7, alle_filterzeilen
assert not alle_verstoesse, alle_verstoesse
assert not alle_ueberall, alle_ueberall
ok(f"(1) {len(alle_filterzeilen)} filter-line call sites in {len(dateien_mit_filterzeilen)} files: "
   "cause only as reason=, no grund= in any security-log call")

# (3a) mutation of the source text — each variant must turn the analysis red
MUTATIONEN = [
    ("oidc.py", "method=oidc reason=account_locked", "method=oidc grund=account_locked"),
    ("webauthn_.py", "method=passkey reason=unknown_key", "method=passkey grund=unknown_key"),
    ("webauthn_.py", 'method=passkey reason=%s"', 'method=passkey grund=%s"'),
    ("manager.py", "method=blocked reason=%s", "method=blocked grund=%s"),
    ("manager.py", "ip=%s reason=pending", "ip=%s grund=pending"),
]
for datei, alt, neu in MUTATIONEN:
    quelle = _lies(os.path.join(PAKET, datei))
    assert quelle.count(alt) == 1, f"{datei}: mutation anchor {alt!r} occurs {quelle.count(alt)}x"
    f, v, _u = _pruefe_quelle(quelle.replace(alt, neu), datei)
    assert v, f"{datei}: '{alt}' -> '{neu}' was not noticed"
# A literal keyword and an event word coming from a constant, each with a differently spelled key:
for snippet in ('seclog.warning("failed login user=%s ip=%s method=password grund=x", u, i)',
                'security.seclog.warning("%s user=%s ip=%s method=x grund=%s", security.LOG_PRUEFUNG, u, i, g)',
                'security.seclog.warning("%s user=%s ip=%s method=x reason_code=%s", '
                'security.log_ereignis(m), u, i, g)',
                'security.seclog.warning("deferred %s user=%s ip=%s grund=pending", "login", u, i)'):
    f, v, _u = _pruefe_quelle(snippet, "snippet")
    assert f and v, f"not noticed: {snippet}"
# Controls: the right spelling and an unrelated line are not flagged.
f, v, u = _pruefe_quelle('security.seclog.warning("%s user=%s ip=%s method=x reason=%s", '
                         'security.LOG_ANMELDUNG, u, i, g)', "snippet")
assert f and not v and not u, (f, v, u)
f, v, u = _pruefe_quelle('security.seclog.warning("something else grund=%s", g)', "snippet")
assert not f and not v and u, "a non-filter line is only caught by the broad check"
ok("(3) mutation: one place bent to grund= in the source text turns the static check red (5 places + 4 forms)")


# ---------------------------------------------------------------------------
# (2) dynamic: real operations -> lines -> the failregex of the shipped files
# ---------------------------------------------------------------------------
def _ohne_datum(zeile):
    return re.sub(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:,\d+)? ", "", zeile)


class _Mitschnitt:
    """The lines of the security log in the format of the shipped file (date stripped, as fail2ban dates by it)."""

    def __enter__(self):
        self.puffer = io.StringIO()
        self.haken = logging.StreamHandler(self.puffer)
        self.haken.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        security.seclog.addHandler(self.haken)
        return self

    def __exit__(self, *_):
        security.seclog.removeHandler(self.haken)

    def zeilen(self):
        return [_ohne_datum(z) for z in self.puffer.getvalue().splitlines() if z.strip()]


def _probleme(zeile, jail, ip, reason=None):
    """Everything wrong with a line that `jail` is supposed to read."""
    fehler = []
    m = _trifft(jail, zeile)
    if not m:
        fehler.append("the jail does not match")
    elif m.group("host") != ip:
        fehler.append(f"host {m.group('host')!r} != {ip!r}")
    if "grund=" in zeile:
        fehler.append("grund= in the line")
    if reason is not None and f" reason={reason}" not in zeile and not (reason == "*" and " reason=" in zeile):
        fehler.append(f"reason={reason} missing")
    return fehler


def _gegenstelle(jail):
    return JAIL_PRUEFUNG if jail is JAIL else JAIL


def _erwarte(zeilen, jail, ip, reason=None, was=""):
    """Exactly the lines of the jail are read by it and NOT by the other one; returns them."""
    assert zeilen, f"{was}: no line"
    for z in zeilen:
        p = _probleme(z, jail, ip, reason)
        assert not p, f"{was}: {p} — {z!r}"
        assert not _trifft(_gegenstelle(jail), z), f"{was}: the other jail reads it too — {z!r}"
    return zeilen


def neu(**cfg):
    grund = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False, csrf_enabled=False,
                 passkey_enabled=False, oidc_enabled=False, base_url="http://testserver")
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# --- local password: wrong sign-in, lockout, verification, deferral -------------------------
IP1 = "203.0.113.41"
auth, app = neu()
uid = auth.create_user("anna", "Anna-Passwort-2026")
cl = TestClient(app, client=(IP1, 1))
with _Mitschnitt() as m:
    cl.post("/auth/login", data={"username": "anna", "password": f"falsch{next(_FALSCH)}"})
zl = _erwarte([z for z in m.zeilen() if z.startswith("WARNING failed")], JAIL, IP1, was="wrong password")
assert "method=password" in zl[0], zl
ok("(2) wrong password: `failed login ... method=password` hits the login jail")

auth.store.clear_fails(username="anna")
for _ in range(auth._sec("max_login_attempts")):
    auth._record_login("anna", IP1, False, "password")
with _Mitschnitt() as m:
    assert auth._is_locked("anna", IP1), "precondition: the lockout applies"
_erwarte(m.zeilen(), JAIL, IP1, reason="lockout_", was="lockout rejection")
assert all("method=blocked" in z for z in m.zeilen()), m.zeilen()
ok("(2) lockout rejection: `failed login ... method=blocked reason=lockout_*` hits the login jail")

auth.store.clear_fails(username="anna")
for _ in range(auth._sec("password_change_max_attempts")):
    auth._record_login("anna", IP1, False, "password_change")
with _Mitschnitt() as m:
    assert auth._is_password_change_locked("anna", IP1), "precondition: the own bucket applies"
_erwarte(m.zeilen(), JAIL_PRUEFUNG, IP1, reason="lockout_password_change", was="verification rejection")
assert all(z.startswith("WARNING failed verification ") for z in m.zeilen()), m.zeilen()
ok("(2) rejection outside the login: `failed verification ... reason=lockout_password_change` hits the verify jail only")

with _Mitschnitt() as m:
    auth._aufgeschoben("anna", IP1)
    auth._aufgeschoben("anna", IP1, login=False)
dz = m.zeilen()
assert [z.split(" user=")[0] for z in dz] == ["WARNING deferred login", "WARNING deferred verification"], dz
for z in dz:
    assert " reason=pending" in z and "grund=" not in z, z
    assert not _trifft(JAIL, z) and not _trifft(JAIL_PRUEFUNG, z), f"a deferral must not ban: {z!r}"
ok("(2) deferral: `deferred login|verification ... reason=pending` — both jails deliberately do NOT read it")

# a miss at the first-admin claim by a signed-in account is no sign-in either: real route
auth_c, app_c = neu()
auth_c.admin_claim_token()
auth_c.create_user("clara", "Clara-Passwort-2026")
ccl = TestClient(app_c, client=(IP1, 1), headers={"Accept": "text/html"})
ccl.post("/auth/login", data={"username": "clara", "password": "Clara-Passwort-2026"})
with _Mitschnitt() as m:
    ccl.get("/auth/claim-admin?token=falsch")
zc = _erwarte([z for z in m.zeilen() if "method=claim_admin" in z], JAIL_PRUEFUNG, IP1, was="claim_admin")
assert zc[0].startswith("WARNING failed verification user=clara "), zc
ok("(2) a miss at the first-admin claim: `failed verification ... method=claim_admin` hits the verify jail only")

# --- API key: denied -----------------------------------------------------------------------
IP2 = "203.0.113.42"
auth_k, app_k = neu()
anna_k = auth_k.create_user("anna", "Anna-Passwort-2026")
schluessel = auth_k.create_api_key(anna_k, name="sync")
auth_k.revoke_api_key(schluessel["id"])
ck = TestClient(app_k, client=(IP2, 1))
with _Mitschnitt() as m:
    ck.get("/auth/me", headers={"X-API-Key": schluessel["key"]})
    ck.get("/auth/me", headers={"X-API-Key": "tsk_" + "x" * 40})
zk = [z for z in m.zeilen() if "api key denied" in z]
assert len(zk) == 2, m.zeilen()
for z, grund in zip(zk, ("revoked", "unknown")):
    assert re.fullmatch(rf"WARNING api key denied user=\S+ ip={re.escape(IP2)} reason={grund}", z), z
    assert "grund=" not in z and not _trifft(JAIL, z) and not _trifft(JAIL_PRUEFUNG, z), z
ok("(2) API key denied: `api key denied user=… ip=… reason=revoked|unknown` (no ban, cause under reason=)")

# --- LDAP: wrong password, outage ---------------------------------------------------------
IP3 = "203.0.113.43"


class _VerzeichnisLeer:
    def authenticate(self, username, password):
        return None


class _VerzeichnisWeg:
    def authenticate(self, username, password):
        from tinysesam.ldap_ import VerzeichnisNichtErreichbar
        raise VerzeichnisNichtErreichbar("connection refused")


auth_l, app_l = neu(ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True)
auth_l.ensure_admin("admin", "Lokal-Passwort-2026")
auth_l.ldap = _VerzeichnisLeer()
cle = TestClient(app_l, client=(IP3, 1))
with _Mitschnitt() as m:
    cle.post("/auth/login", data={"username": "lena", "password": f"falsch{next(_FALSCH)}"})
zl = _erwarte([z for z in m.zeilen() if z.startswith("WARNING failed")], JAIL, IP3, was="LDAP wrong password")
assert "method=password" in zl[0], zl
ok("(2) LDAP wrong password: `failed login ... method=password` hits the login jail")

auth_l.ldap = _VerzeichnisWeg()
with _Mitschnitt() as m:
    cle.post("/auth/login", data={"username": "lena", "password": f"falsch{next(_FALSCH)}"})
zw = [z for z in m.zeilen() if "LDAP unreachable" in z]
assert zw and all(" reason=" in z and "grund=" not in z for z in zw), m.zeilen()
assert not any(_trifft(JAIL, z) or _trifft(JAIL_PRUEFUNG, z) for z in m.zeilen()), \
    f"an outage must not ban: {m.zeilen()}"
ok("(2) LDAP outage: `LDAP unreachable ... reason=` and no ban line (no failed attempt)")

# --- passkey (needs the extra `webauthn`) --------------------------------------------------
IP4 = "203.0.113.44"
if _extra_da("webauthn"):
    auth_p, app_p = neu(passkey_enabled=True, rp_id="localhost", origin="http://localhost:8000")
    uid_p = auth_p.create_user("paula", "Paula-Passwort-2026")
    auth_p.store.add_webauthn(uid_p, "Y3JlZC10ZXN0", "pk", 0, [], "Testschluessel")
    cp = TestClient(app_p, client=(IP4, 1))

    def _passkey_finish(kennung):
        cp.post("/auth/passkey/login/begin")
        cp.post("/auth/passkey/login/finish", content=('{"id": "%s", "rawId": "%s"}' % (kennung, kennung)))

    with _Mitschnitt() as m:
        _passkey_finish("gibtsnicht")
    zu = _erwarte([z for z in m.zeilen() if "method=passkey" in z], JAIL, IP4, reason="unknown_key",
                  was="passkey unknown key")
    ok("(2) passkey, unknown key: `failed login ... method=passkey reason=unknown_key` hits the login jail")
    with _Mitschnitt() as m:
        _passkey_finish("Y3JlZC10ZXN0")
    zf = _erwarte([z for z in m.zeilen() if "method=passkey" in z], JAIL, IP4, reason="*",
                  was="passkey failed verification")
    assert "user=paula " in zf[0] and re.search(r"reason=[A-Za-z]+$", zf[0]), zf
    ok("(2) passkey, failed check: `failed login user=<owner> ... method=passkey reason=<ExceptionType>` hits the login jail")
else:
    print("  - passkey: extra `webauthn` missing -> dynamic part SKIPPED (call sites covered by (1))")

# --- SSO with a locked account (needs the extra `authlib`) ---------------------------------
IP5 = "203.0.113.45"
if _extra_da("authlib"):
    from urllib.parse import parse_qs, urlparse

    IDP = "https://idp.example.invalid"

    class _Claims(dict):
        def validate(self, *a, **k):
            pass

    claims = {"sub": "gesperrt-1", "preferred_username": "gesperrt", "email": "gesperrt@example.com",
              "email_verified": True}
    auth_o, app_o = neu(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="geheim")
    auth_o.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize",
                         "token_endpoint": IDP + "/token", "userinfo_endpoint": IDP + "/userinfo",
                         "jwks_uri": IDP + "/jwks"}
    auth_o.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})
    auth_o.oidc.userinfo = lambda at, erwartetes_sub="": {}

    def _sso_login():
        c = TestClient(app_o, client=(IP5, 1))
        start = c.get("/auth/oidc/start", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        return c.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)

    _sso_login()                                              # the first sign-in creates the account
    konto = auth_o.store.get_user_by_name("gesperrt")
    assert konto, "precondition: the SSO account exists"
    auth_o.store.set_disabled(konto["id"], True)
    with _Mitschnitt() as m:
        antwort = _sso_login()
    assert antwort.status_code == 403, antwort.status_code
    zo = _erwarte([z for z in m.zeilen() if "method=oidc" in z], JAIL, IP5, reason="account_locked",
                  was="SSO locked account")
    ok("(2) SSO, locked account: `failed login ... method=oidc reason=account_locked` hits the login jail")
else:
    print("  - SSO: extra `authlib` missing -> dynamic part SKIPPED (call site covered by (1))")

# --- (3b) mutation in the running process: one place writes grund= ------------------------
auth_m, _ = neu()
auth_m.create_user("mia", "Mia-Passwort-2026")
IP6 = "203.0.113.46"
with _Mitschnitt() as m:
    auth_m._abgewiesen("mia", IP6, "lockout_user")                      # real code, untouched
sauber = m.zeilen()[-1]
assert not _probleme(sauber, JAIL, IP6, reason="lockout_user"), sauber

_original = security.seclog.warning


def _verbogen(msg, *a, **k):
    return _original(msg.replace("reason=", "grund="), *a, **k)


security.seclog.warning = _verbogen        # an instance attribute shadows the method, `del` restores it
try:
    with _Mitschnitt() as m:
        auth_m._abgewiesen("mia", IP6, "lockout_user")
finally:
    del security.seclog.warning
assert security.seclog.warning == _original, "the mutation was not reverted"
kaputt = m.zeilen()[-1]
assert "grund=lockout_user" in kaputt, kaputt
assert _probleme(kaputt, JAIL, IP6, reason="lockout_user"), "the dynamic check does not notice grund="
assert not _trifft(JAIL, kaputt), (
    "premise gone: a line with grund= is still read by the jail — then reason= no longer matters, "
    f"check the failregex: {kaputt!r}")
ok("(3) mutation in the process: a place writing grund= falls out of the jail (and the check notices it)")

print("\nFAIL2BAN-REASON OK ✅")
