"""security_log: the fail2ban logger writes to the file the bundled jail points to.

Without this field the handler had to be wired by hand — the jail in deploy/fail2ban/ pointed
to a file that never came into existence, and silently ran into the void.
"""
import contextlib
import io
import logging
import os
import re
import stat
import tempfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, security
from tinysesam.errors import ConfigError


def _lies(pfad):
    """Read a file completely and close the handle again.

    `open(...).read()` leaves the handle open until the next collection; CodeQL rightly reports it
    (py/file-not-closed), and inside an `assert` the read would also be a
    side effect that vanishes together with the check under `python -O`.
    """
    with open(pfad, encoding="utf-8") as fh:
        return fh.read()



def ok(name):
    print(f"  ✓ {name}")


def _abraeumen():
    for h in list(security.seclog.handlers):
        if getattr(h, "_tinysesam_path", None):
            security.seclog.removeHandler(h)
            h.close()


_abraeumen()
tmp = tempfile.mkdtemp()
logdatei = os.path.join(tmp, "security.log")
db = os.path.join(tempfile.mkdtemp(), "t.db")

auth = TinySesam(TinySesamConfig(db_path=db, security_log=logdatei, cookie_secure=False,
                                 passkey_enabled=False, csrf_enabled=False))
auth.create_user("anna", "geheim123-lang-genug")
assert os.path.exists(logdatei)
ok("security_log set → file is created")

# one failed attempt — exactly the line that deploy/fail2ban/tinysesam-filter.conf matches
auth._check_password("anna", "falsch")
auth._record_login("anna", "203.0.113.7", False, "password")
with open(logdatei, encoding="utf-8") as fh:
    inhalt = fh.read()
assert "failed login user=anna ip=203.0.113.7" in inhalt, inhalt
ok("failed attempt ends up in the file")

muster = re.compile(r"failed login user=.* ip=(?P<host>\S+) method=.*")   # = failregex of the jail
zeile = [z for z in inhalt.splitlines() if "failed login" in z][0]
assert muster.search(zeile).group("host") == "203.0.113.7"
assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", zeile), zeile
ok("line matches the jail's failregex and carries the timestamp up front (fail2ban dates by it)")

# a second instance on the same path must not write twice
vorher = len([h for h in security.seclog.handlers if getattr(h, "_tinysesam_path", None) == logdatei])
security.attach_security_log(logdatei)
nachher = len([h for h in security.seclog.handlers if getattr(h, "_tinysesam_path", None) == logdatei])
assert vorher == nachher == 1
ok("idempotent: the same path is not attached twice")

# unwritable path: warn but keep running — a log file must not disable sign-in
assert security.attach_security_log(os.path.join(tmp, "gibtsnicht", "x.log")) is False
db2 = os.path.join(tempfile.mkdtemp(), "t.db")
TinySesam(TinySesamConfig(db_path=db2, security_log="/proc/darf/ich/nicht.log",
                          cookie_secure=False, passkey_enabled=False))
ok("unwritable path → False + warning, startup continues")

# without security_log everything stays as before: no file handler
_abraeumen()
db3 = os.path.join(tempfile.mkdtemp(), "t.db")
TinySesam(TinySesamConfig(db_path=db3, cookie_secure=False, passkey_enabled=False))
assert not [h for h in security.seclog.handlers if getattr(h, "_tinysesam_path", None)]
ok("no handler without security_log (whoever sets up their own logging keeps it)")

# ---------------------------------------------------------------------------
# B5-03: the first-admin one-time token must NOT appear in this file.
#
# Up to 0.18.x the constructor wrote "…/auth/claim-admin?token=<value>…" via seclog — i.e.
# exactly into the file the bundled fail2ban jail points to, which logrotate archives
# and which (as measured) was created with -rw-rw-r--. Anyone who could read it and had any account on the
# instance thereby became admin.
# ---------------------------------------------------------------------------
_abraeumen()
alte_maske = os.umask(0o000)          # the case in which the file used to be created world-readable
try:
    tmp2 = tempfile.mkdtemp()
    log2 = os.path.join(tmp2, "security.log")
    db4 = os.path.join(tmp2, "t.db")

    class _Konsole(io.StringIO):
        # stderr on a terminal: only then does the token go to stderr. Without a console (container,
        # journal) TinySesam has written `<db_path>.claim` since 0.22.0 — tests/test_operations_findings.py (b).
        def isatty(self):
            return True

    stderr = _Konsole()
    with contextlib.redirect_stderr(stderr):
        auth2 = TinySesam(TinySesamConfig(db_path=db4, security_log=log2, cookie_secure=False,
                                          passkey_enabled=False, allow_signup=True,
                                          signup_require_email=False))
    inhalt2 = _lies(log2)

    # Precondition: there IS a token to leak. Without this check everything that follows would be green
    # even if the bootstrap path were simply switched off — the test would then measure nothing.
    token = auth2.admin_claim_token()
    assert token and len(token) >= 20, token
    assert "Kein Admin vorhanden" in inhalt2, inhalt2      # the line is still written
    ok("precondition: without an admin a one-time token is created and the log reports the situation")

    # The attack: the PoC read the value from the log file with exactly this pattern.
    assert not re.search(r"claim-admin\?token=(\S+)", inhalt2), inhalt2
    assert token not in inhalt2, inhalt2
    ok("B5-03: the token value is NOT in the file fail2ban reads")

    assert "steht auf der Konsole (stderr), nicht in dieser Zeile" in inhalt2, inhalt2
    ok("the log names only the retrieval route, not the value")

    modus = stat.S_IMODE(os.stat(log2).st_mode)
    assert modus == 0o640, oct(modus)
    ok("the log file is created with 0640 instead of the umask (not world-readable)")

    # … and again after a rotation: logrotate removes the file, the handler recreates it.
    os.remove(log2)
    security.seclog.warning("failed login user=b5 ip=203.0.113.9 method=password")
    assert stat.S_IMODE(os.stat(log2).st_mode) == 0o640, oct(stat.S_IMODE(os.stat(log2).st_mode))
    ok("the file recreated after a rotation also carries 0640")

    # The legitimate route 1: whoever starts the service sees the token on the console.
    assert f"/auth/claim-admin?token={token}" in stderr.getvalue(), stderr.getvalue()
    ok("legitimate route: the operator gets the token on stderr")

    # The legitimate route 2: a dedicated file with 0600 — and the token keeps working there.
    _abraeumen()
    tmp3 = tempfile.mkdtemp()
    log3 = os.path.join(tmp3, "security.log")
    tokdatei = os.path.join(tmp3, "admin-claim.token")
    open(tokdatei, "w").close()                    # already present and open: permissions must apply
    os.chmod(tokdatei, 0o666)
    db5 = os.path.join(tmp3, "t.db")
    with contextlib.redirect_stderr(io.StringIO()):
        auth3 = TinySesam(TinySesamConfig(db_path=db5, security_log=log3, cookie_secure=False,
                                          passkey_enabled=False, csrf_enabled=False,
                                          allow_signup=True, signup_require_email=False,
                                          admin_claim_token_file=tokdatei))
    tok3 = _lies(tokdatei).strip()
    assert tok3 == auth3.admin_claim_token(), tok3
    assert stat.S_IMODE(os.stat(tokdatei).st_mode) == 0o600, oct(stat.S_IMODE(os.stat(tokdatei).st_mode))
    _log3 = _lies(log3)
    assert tok3 not in _log3
    assert tokdatei in _log3                                   # the path may be named
    ok("admin_claim_token_file: value in a dedicated file with 0600, log names only the path")

    app = FastAPI()
    app.include_router(auth3.router())
    c = TestClient(app)
    r = c.post("/auth/register", data={"username": "betreiber", "password": "geheim123-lang-genug"},
               follow_redirects=False)
    assert r.status_code == 303, r.status_code
    r = c.get(f"/auth/claim-admin?token={tok3}", follow_redirects=False)
    assert r.status_code == 303, r.status_code
    assert auth3.store.get_user_by_name("betreiber")["is_admin"]
    ok("legitimate route stays intact: the token from the 0600 file makes the first admin")

    # And the file must not be the log again — otherwise the value would stand exactly there.
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  security_log=log3, admin_claim_token_file=log3,
                                  cookie_secure=False, passkey_enabled=False))
        raise AssertionError("admin_claim_token_file == security_log wurde angenommen")
    except ConfigError as e:
        assert "dieselbe Datei" in str(e), str(e)
    ok("configuration check: admin_claim_token_file must not be the security_log")
finally:
    os.umask(alte_maske)

# ---------------------------------------------------------------------------
# Three promises from the same fix that nobody has measured so far (follow-up to B5-03):
# an already existing world-readable file is REPORTED, the token file is TRUNCATED before
# writing, and a token file without a token route is caught by the configuration check.
# Each of these lines could be rolled back without any suite turning red.
# ---------------------------------------------------------------------------

# (1) Existing file: do not rewrite it (that would be an operator decision), but say so.
_abraeumen()
tmp5 = tempfile.mkdtemp()
log5 = os.path.join(tmp5, "security.log")
open(log5, "w").close()
os.chmod(log5, 0o666)                       # how it was created before the fix: umask-dependent, world-readable
puffer5 = io.StringIO()
haken5 = logging.StreamHandler(puffer5)
security.seclog.addHandler(haken5)
try:
    assert security.attach_security_log(log5) is True
finally:
    security.seclog.removeHandler(haken5)
text5 = puffer5.getvalue()
assert "welt-lesbar" in text5, f"no message: {text5[:160]!r}"
assert log5 in text5 and "chmod 640" in text5, text5[:200]
assert stat.S_IMODE(os.stat(log5).st_mode) == 0o666, "the existing file was rewritten"
ok("an already existing world-readable log file is reported (and not rewritten)")

# Control: an already tight file stays silent — otherwise the warning would be noise nobody reads.
_abraeumen()
log5b = os.path.join(tmp5, "eng.log")
open(log5b, "w").close()
os.chmod(log5b, 0o640)
puffer5b = io.StringIO()
haken5b = logging.StreamHandler(puffer5b)
security.seclog.addHandler(haken5b)
try:
    security.attach_security_log(log5b)
finally:
    security.seclog.removeHandler(haken5b)
assert "welt-lesbar" not in puffer5b.getvalue(), puffer5b.getvalue()[:160]
ok("...an already tight file does not report")

# (2) The token file is truncated before writing. Without `os.ftruncate` the tail of a longer
#     predecessor file would remain — an expired token that still looks like
#     one, and a file from which it is unclear which line applies.
_abraeumen()
tmp6 = tempfile.mkdtemp()
tokdatei6 = os.path.join(tmp6, "admin-claim.token")
with open(tokdatei6, "w", encoding="utf-8") as fh:
    fh.write("ALTES-TOKEN-AUS-EINEM-FRUEHEREN-LAUF-VIEL-LAENGER-ALS-DAS-NEUE-0123456789\n")
os.chmod(tokdatei6, 0o600)
with contextlib.redirect_stderr(io.StringIO()):
    auth6 = TinySesam(TinySesamConfig(db_path=os.path.join(tmp6, "t.db"), cookie_secure=False,
                                      passkey_enabled=False, csrf_enabled=False,
                                      admin_claim_token_file=tokdatei6))
inhalt6 = _lies(tokdatei6)
assert inhalt6 == auth6.admin_claim_token() + "\n", repr(inhalt6)
assert "ALTES-TOKEN" not in inhalt6, f"remainder of the predecessor file: {inhalt6!r}"
ok("the token file is truncated — no remainder of a longer predecessor")

# (3) Token file set, token route off: the file is never created. Without a warning the
#     operator waits for a token that never comes.
from tinysesam.config_check import check_config                                    # noqa: E402

_gemeinsam7 = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   admin_claim_token_file=os.path.join(tmp6, "claim.token"))
for _lage, _cfg in (("admin_claim_ttl_min=0", TinySesamConfig(admin_claim_ttl_min=0, **_gemeinsam7)),
                    ("admin_enabled=False", TinySesamConfig(admin_enabled=False, **_gemeinsam7))):
    _f7, _w7 = check_config(_cfg)
    assert any("admin_claim_token_file ist gesetzt" in w and "nie geschrieben" in w for w in _w7), \
        f"{_lage}: no warning — {_w7!r}"
    assert not _f7, _f7
_f7, _w7 = check_config(TinySesamConfig(**_gemeinsam7))          # route on → silent
assert not any("admin_claim_token_file ist gesetzt" in w for w in _w7), _w7
ok("admin_claim_token_file without a token route is reported at setup (with a route: silent)")

# (3b) …and this warning must name a route that EXISTS. It advised „Der Erst-Admin kommt
#      dann nur über admin_identifiers oder die CLI zustande" — the same false CLI promise that
#      the CHANGELOG explicitly retracted elsewhere („Das CLI stand hier
#      zunächst mit in der Liste — es kann gar keine Konten anlegen"), this time in a text that
#      the operator gets to read. Whoever followed it searched for a command that does not exist.
_f8, _w8 = check_config(TinySesamConfig(admin_claim_ttl_min=0, **_gemeinsam7))
_zeile8 = next(w for w in _w8 if "admin_claim_token_file ist gesetzt" in w)
assert "ensure_admin" in _zeile8 and hasattr(TinySesam, "ensure_admin"), \
    f"the warning names no route that exists: {_zeile8!r}"
assert "oder die CLI zustande" not in _zeile8, \
    f"the CLI creates no accounts — it must not appear here as a route: {_zeile8!r}"
# Control: the CLI really cannot do it. `main()` knows exactly these seven commands;
# if one were added that creates accounts, the line above would have to be changed rather than kept.
import inspect as _inspect  # noqa: E402
from tinysesam.__main__ import main as _cli_main  # noqa: E402

_kommandos = set(re.findall(r'cmd == "([a-z]+)"', _inspect.getsource(_cli_main)))
# `owner` (2026-09-24) creates no account and changes no identifier — it sets the owner role of an
# existing account (emergency route when no owner can get in anymore). `rename` (G13, 2026-09-26) likewise
# creates no account but does change an identifier — which is why the startup messages on
# identifier collisions and control characters now name it (tests/test_security_findings.py checks that
# the named route exists); the first-admin warning here stays as it is.
assert _kommandos == {"version", "passwd", "backup", "restore", "gc", "audit", "unlock", "owner",
                      "rename"}, \
    (f"CLI commands changed: {sorted(_kommandos)} — if one of them can now create accounts "
     "or change identifiers, the operator messages must be changed along")
ok("first-admin warning names ensure_admin instead of the CLI (which creates no accounts)")

# (4) Finding B-regression-6: the notice „Kein vertrauenswürdiger öffentlicher Host" came with
#     EVERY anonymous forward-auth request. `forward_login_url()` has asked `public_base()` since N1,
#     and without `base_url` (allowed: forward_auth_enabled is only a warning) the
#     derived base does not survive the check. A page load with twenty sub-resources
#     wrote twenty identical lines — into the file the fail2ban jail points to and which
#     logrotate keeps for weeks. The line stays, the storm goes.
_abraeumen()
security._GEMELDET.clear()            # process-wide state: the run must be repeatable
tmp8 = tempfile.mkdtemp()
log8 = os.path.join(tmp8, "security.log")
auth8 = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  security_log=log8, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, forward_auth_enabled=True))
app8 = FastAPI()
app8.include_router(auth8.router())
c8 = TestClient(app8)


def _hinweiszeilen(pfad, host=None) -> int:
    with open(pfad, encoding="utf-8") as fh:
        return len([z for z in fh if "Kein vertrauenswürdiger öffentlicher Host" in z
                    and (host is None or host in z)])


for _i in range(20):
    c8.get("/auth/forward", headers={"x-forwarded-proto": "https",
                                     "x-forwarded-host": "app.example.com",
                                     "x-forwarded-uri": f"/asset{_i}.css"})
assert _hinweiszeilen(log8) == 1, \
    f"{_hinweiszeilen(log8)} lines after 20 requests — a crawler bloats the fail2ban file"
ok("the notice about the missing base comes once, not per request")

c8.get("/auth/forward", headers={"x-forwarded-proto": "https",
                                 "x-forwarded-host": "zweiter.example.com",
                                 "x-forwarded-uri": "/"})
assert _hinweiszeilen(log8, "zweiter.example.com") == 1, \
    "a DIFFERENT host no longer gets a line of its own — then the spot falls silent on new cases"
ok("...another host is reported nonetheless (silent is not the same as mute)")

# The cap: the key comes from the request. Whoever probes through the Host header must fill neither
# the file nor memory — from `_GEMELDET_MAX` on the spot falls silent.
security.einmal_melden_zuruecksetzen()
T0 = 1_000_000.0
assert all(security.einmal_melden(f"probe:{i}", jetzt=T0) for i in range(security._GEMELDET_MAX))
assert not security.einmal_melden("probe:noch einer", jetzt=T0), "without a cap an attacker fills the memory"
assert not security.einmal_melden("probe:0", jetzt=T0), "the same key does not report twice"
ok("einmal_melden() is capped (the key comes from the request)")

# C-4: The cap must not hold forever. Before, 512 invented Host values sufficed to silence the
# spot until restart — after that the notice about the REAL
# operational error was missing too. An attacker could thereby switch off a warning deliberately, not just make
# noise. (Mutation probe: remove the window change in `einmal_melden` → the next line
# turns red, the rest of the suite stays green.)
assert security.einmal_melden("probe:nach dem Fenster", jetzt=T0 + security._GEMELDET_FENSTER_SEK), \
    "after the window the spot must speak again"
assert security.einmal_melden("probe:0", jetzt=T0 + security._GEMELDET_FENSTER_SEK), \
    "the memory of the old window is emptied"
assert len(security._GEMELDET) == 2, "the new window starts at zero, not at 512"
ok("...and the cap applies per time window, not for the lifetime of the process")

# And the suppression itself is visible: exactly one line per window, otherwise „from here on
# I stay silent" would be a second silent hole.
security.einmal_melden_zuruecksetzen()
_puffer_deckel = io.StringIO()
_haken_deckel = logging.StreamHandler(_puffer_deckel)
security.seclog.addHandler(_haken_deckel)
try:
    for i in range(security._GEMELDET_MAX):
        security.einmal_melden(f"voll:{i}", jetzt=T0)
    for i in range(3):
        security.einmal_melden(f"zuviel:{i}", jetzt=T0)
finally:
    security.seclog.removeHandler(_haken_deckel)
_text_deckel = _puffer_deckel.getvalue()
assert _text_deckel.count("Hinweis-Deckel erreicht") == 1, \
    f"exactly one line per window, not {_text_deckel.count('Hinweis-Deckel erreicht')}: {_text_deckel[:200]!r}"
assert str(security._GEMELDET_MAX) in _text_deckel, _text_deckel[:200]
security.einmal_melden_zuruecksetzen()
ok("...and reaching the cap is reported once (no invisible suppression)")

# (5) The same brake for the opposite case: if `base_url` is set, it WINS — even against a
#     passed-in base on a second own host. Entirely silent would be a trap for the
#     developer (their value vanishes), per request it would be the next storm (the value comes
#     from the Host header in this pattern). So once per host.
_abraeumen()
tmp9 = tempfile.mkdtemp()
log9 = os.path.join(tmp9, "security.log")
auth9 = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  security_log=log9, cookie_secure=False, passkey_enabled=False,
                                  base_url="https://auth.example.com",
                                  trusted_redirect_hosts=["app-b.example.com"]))
for _ in range(5):
    assert auth9.magic_url("tok", "https://app-b.example.com", "reset_password").startswith(
        "https://auth.example.com/"), "base_url must win even against a second own name"
with open(log9, encoding="utf-8") as fh:
    _ersetzt = [z for z in fh if "wird durch base_url" in z]
assert len(_ersetzt) == 1, f"{len(_ersetzt)} lines after 5 calls — once per address, not per request"
security.einmal_melden_zuruecksetzen()
ok("a replaced base reports once per address (not silent, not as a storm)")

# C-5: The same case with the SAME host but a different path. The CHANGELOG promises a line
# when base_url replaces a deviating value — before, only the host was checked, so exactly the case
# that arrives at the recipient as a 404 stayed silent: an app mounted under `/sso` whose
# own form passes `https://auth.example.com/falsch` through.
# (Mutation probe: turn the comparison back to `_host_aus(...)` → the next
# assertion turns red.)
_abraeumen()
tmp10 = tempfile.mkdtemp()
log10 = os.path.join(tmp10, "security.log")
auth10 = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                   security_log=log10, cookie_secure=False, passkey_enabled=False,
                                   base_url="https://auth.example.com/sso"))
security.einmal_melden_zuruecksetzen()
for _ in range(4):
    _link = auth10.magic_url("tok", "https://auth.example.com/falsch", "reset_password")
    assert _link.startswith("https://auth.example.com/sso/"), _link
_zeilen10 = [z for z in _lies(log10).splitlines() if "wird durch base_url" in z]
assert len(_zeilen10) == 1, \
    f"same host, different path: {len(_zeilen10)} lines — exactly one expected"
assert "/falsch" in _zeilen10[0] and "/sso" in _zeilen10[0], _zeilen10[0][:200]

# Control: the same address as base_url (just with a trailing slash) is no deviation
# and must not report — otherwise the line would be noise.
security.einmal_melden_zuruecksetzen()
_vorher10 = len(_lies(log10).splitlines())
auth10.magic_url("tok", "https://auth.example.com/sso/", "reset_password")
assert len(_lies(log10).splitlines()) == _vorher10, "an identical value is no replacement"
security.einmal_melden_zuruecksetzen()
ok("...also with the same host and a deviating path (and silence for an identical value)")

# C-7: The CONFIGURED base goes through the same form check as the derived one. Before, it saw
# only strip()/rstrip("/") — a user value in the host thus stood in every link, a
# fragment would have cut off the appended token.
for _kaputt in ("https://auth.example.com/x#y", "https://auth.example.com/x?y=1",
                "https://auth.example.com/a/../b", "https://auth.example.com:99999", "auth.example.com"):
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  cookie_secure=False, passkey_enabled=False,
                                  base_url=_kaputt, oidc_enabled=False))
        raise AssertionError(f"base_url={_kaputt!r} kam durch die Konfigurationsprüfung")
    except ConfigError:
        pass
# A user value is usable but gets removed — the check says so instead of doing it silently.
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False,
                              passkey_enabled=False, base_url="https://wer:was@auth.example.com"))
    raise AssertionError("die veränderte Adresse wurde nicht gemeldet")
except ConfigError as _e:
    # Checked against the canonical value in its quoted form, not by substring: otherwise
    # "https://auth.example.com.angreifer.test" anywhere in the text would suffice (CodeQL
    # py/incomplete-url-substring-sanitization).
    assert "wird als" in str(_e) and repr("https://auth.example.com") in str(_e), str(_e)[:200]
ok("base_url is checked by the same rule as a derived base (C-7)")

# ---------------------------------------------------------------------------
# Round 2: A misstep that was NOT a sign-in must not hit the bundled jail.
#
# Since R4-10 the old-password query of the account page is logged as well — rightly so, before
# it was a silent oracle. But it wrote `failed login`, character for character the line
# that `deploy/fail2ban/tinysesam-jail.conf` bans on with `maxretry = 6`. Measured: eight
# missteps by a SIGNED-IN user at their own old password produced eight matching
# lines — the legitimate user locked themselves out at firewall level, for the whole instance.
# Aggravating: from the app lockout on, every further click produced another matching line.
# Now these lines carry an event word of their own (`security.LOG_PRUEFUNG`).
#
# The check runs against the SHIPPED filter files, not against a pattern in the test: otherwise
# the test measures its own copy and does not notice when the template drifts apart.
# ---------------------------------------------------------------------------
_abraeumen()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _failregex(datei):
    text = _lies(os.path.join(ROOT, "deploy", "fail2ban", datei))
    zeile = [z for z in text.splitlines() if z.startswith("failregex =")][0]
    muster = zeile.split("=", 1)[1].strip().replace("<HOST>", r"(?P<host>\S+)")
    return re.compile(muster)


JAIL = _failregex("tinysesam-filter.conf")                 # bans: real sign-in attempts
JAIL_PRUEFUNG = _failregex("tinysesam-verify-filter.conf")  # the second, milder jail


def _ohne_datum(zeile):
    """How fail2ban sees the line: it dates by the timestamp itself, the rest is matched."""
    return re.sub(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:,\d+)? ", "", zeile)


class _Mitschnitt:
    """Captures the lines of the security log in the format of the shipped file."""

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


dbf = os.path.join(tempfile.mkdtemp(), "t.db")
authf = TinySesam(TinySesamConfig(db_path=dbf, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, lang="de"))
uid_f = authf.create_user("anna", "Anna-Passwort-2026")

# (1) Each method individually: sign-in attempts hit the jail, everything else does not.
for methode in ("password", "pin", "totp"):
    with _Mitschnitt() as m:
        authf._record_login("anna", "203.0.113.4", False, methode)
    zeile = m.zeilen()[-1]
    assert JAIL.search(zeile), f"{methode}: the jail does not see the sign-in attempt — {zeile!r}"
    assert JAIL.search(zeile).group("host") == "203.0.113.4", zeile
    assert not JAIL_PRUEFUNG.search(zeile), f"{methode} ends up in the milder jail: {zeile!r}"
for methode in security.NICHT_LOGIN_METHODEN:
    with _Mitschnitt() as m:
        authf._record_login("anna", "203.0.113.4", False, methode)
    zeile = m.zeilen()[-1]
    assert not JAIL.search(zeile), f"{methode} hits the bundled login jail: {zeile!r}"
    assert JAIL_PRUEFUNG.search(zeile), f"{methode} does not hit the second jail either: {zeile!r}"
    assert f"method={methode}" in zeile, zeile
ok("event word separates: only real sign-in attempts hit the jail's failregex")

# (2) The REJECTION (app lockout already active) sticks to it as well — otherwise the
# problem would just move by one line: from the lock on every click produces another.
authf.store.clear_fails(username="anna")
for _ in range(authf._sec("max_login_attempts")):
    authf._record_login("anna", "203.0.113.4", False, "password")
with _Mitschnitt() as m:
    assert authf._is_locked("anna", "203.0.113.4"), "precondition: the login lockout kicks in"
assert JAIL.search(m.zeilen()[-1]), f"the login rejection is invisible to the jail: {m.zeilen()[-1]!r}"
authf.store.clear_fails(username="anna")
for _ in range(authf._sec("password_change_max_attempts")):
    authf._record_login("anna", "203.0.113.4", False, "password_change")
with _Mitschnitt() as m:
    assert authf._is_password_change_locked("anna", "203.0.113.4"), "precondition: the dedicated bucket kicks in"
zeile = m.zeilen()[-1]
assert "reason=lockout_password_change" in zeile, zeile
assert not JAIL.search(zeile), f"the rejection of the dedicated bucket hits the login jail: {zeile!r}"
assert JAIL_PRUEFUNG.search(zeile), zeile
ok("the rejections also carry the word of their bucket (reason stays in the log)")

# (3) The measured case from the round: eight missteps by a SIGNED-IN user at their own
# old password — with `maxretry = 6` that was a self-ban at firewall level.
authf.store.clear_fails(username="anna")
appf = FastAPI()
appf.include_router(authf.router())
cf = TestClient(appf)
tok_f, _ = authf.start_session(uid_f, "password", remember=True)
cf.cookies.set(authf.cfg.session_cookie, tok_f)
with _Mitschnitt() as m:
    codes = [cf.post("/auth/password", json={"current": f"vertippt{i}", "new": "neues-langes-passwort"}).status_code
             for i in range(8)]
assert 403 in codes and 429 in codes, codes          # guessing happened, and the app lock kicked in
zeilen_f = [z for z in m.zeilen() if "user=anna" in z]
assert len(zeilen_f) == 8, f"{len(zeilen_f)} lines — the operation is no longer logged"
treffer = [z for z in zeilen_f if JAIL.search(z)]
assert not treffer, f"{len(treffer)} of 8 lines ban the legitimate user: {treffer[:1]}"
assert all(JAIL_PRUEFUNG.search(z) for z in zeilen_f), zeilen_f[:1]
ok("eight typos at one's own password change: logged, but no hit of the login jail")

# (4) And the control, so that (3) does not merely measure that nothing triggers anymore: the same
# attack from outside — failed sign-ins at the login — still fills the jail.
with _Mitschnitt() as m:
    for i in range(6):
        cf.post("/auth/login", data={"username": "anna", "password": f"falsch{i}"})
treffer = [z for z in m.zeilen() if JAIL.search(z)]
assert len(treffer) >= 6, f"only {len(treffer)} bannable lines — the jail gets too little to read"
ok("control: failed sign-ins at the login still hit the jail")
os.remove(dbf)

# (5) `is_pin_locked` reports its rejection like any other lock. Until T-13 it was the
# only one to reject silently — fail2ban got nothing to read exactly when it was supposed to ban. At the login
# the PIN is a sign-in attempt (`failed login`), on the step-up page it is not.
# (Mutation probe: in `is_pin_locked` count only again, without `_sperre_pruefen` → red.)
dbp = os.path.join(tempfile.mkdtemp(), "t.db")
authp = TinySesam(TinySesamConfig(db_path=dbp, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, lang="de", pin_enabled=True, pin_login=True))
authp.create_user("paul", "Paul-Passwort-2026")
for _ in range(authp._sec("pin_max_attempts")):
    authp._record_login("paul", "203.0.113.5", False, "pin")
with _Mitschnitt() as m:
    assert authp._is_pin_locked("paul", "203.0.113.5"), "precondition: the PIN bucket kicks in"
zeilen_p = [z for z in m.zeilen() if "reason=lockout_pin" in z]
assert zeilen_p and JAIL.search(zeilen_p[-1]), f"the PIN lock rejects silently: {m.zeilen()!r}"
with _Mitschnitt() as m:
    assert authp._is_pin_locked("paul", "203.0.113.5", login=False)
assert m.zeilen() and not JAIL.search(m.zeilen()[-1]) and JAIL_PRUEFUNG.search(m.zeilen()[-1]), \
    f"on the step-up page the PIN lock is not a sign-in: {m.zeilen()!r}"
ok("is_pin_locked reports the rejection (login: failed login, step-up: failed verification)")
os.remove(dbp)

# (6) B5-16: Missteps at /auth/claim-admin — throttled and logged. Until T-13 a
# signed-in account could guess here as often as it liked, without a trace. (Mutation probe:
# remove `admin_claim_failure` from the router → no line, no audit.)
dbc = os.path.join(tempfile.mkdtemp(), "t.db")
authc = TinySesam(TinySesamConfig(db_path=dbc, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, lang="de"))
authc.admin_claim_token()
authc.create_user("clara", "Clara-Passwort-2026")
authc.set_security("rate_limit_max", 5)
appc = FastAPI()
appc.include_router(authc.router())
cc = TestClient(appc, headers={"Accept": "text/html"})
cc.post("/auth/login", data={"username": "clara", "password": "Clara-Passwort-2026"})
with _Mitschnitt() as m:
    codes = [cc.get(f"/auth/claim-admin?token=rate{i}").status_code for i in range(8)]
assert 403 in codes and codes[-1] == 429, f"B5-16: /auth/claim-admin is not throttled: {codes}"
zeilen_c = [z for z in m.zeilen() if "method=claim_admin" in z]
assert len(zeilen_c) == codes.count(403), f"B5-16: {len(zeilen_c)} lines for {codes.count(403)} missteps"
assert all(JAIL_PRUEFUNG.search(z) and not JAIL.search(z) for z in zeilen_c), zeilen_c[:1]
fehl = [z for z in authc.store.recent_audit(50) if z["event"] == "admin_claim_fail"]
assert len(fehl) == codes.count(403) and fehl[0]["username"] == "clara" and fehl[0]["ip"], fehl[:1]
ok("B5-16: missteps at the first-admin claim are throttled, in the audit and in the security log")
os.remove(dbc)

# (7) The resource PIN writes a reason that can be evaluated. `res:<name>` is never an
# account — until T-13 every misstep had `grund=kein_konto`.
dbr = os.path.join(tempfile.mkdtemp(), "t.db")
authr = TinySesam(TinySesamConfig(db_path=dbr, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, lang="de"))
authr._record_login("res:lager", "203.0.113.6", False, "resource")
detail = [z["detail"] for z in authr.store.recent_audit(5) if z["event"] == "login_fail"][0]
assert "grund=falsches_bereichsgeheimnis" in detail and "kein_konto" not in detail, detail
ok("resource PIN: grund=falsches_bereichsgeheimnis instead of the misleading kein_konto")
os.remove(dbr)

_abraeumen()
for f in (db, db2, db3):
    if os.path.exists(f):
        os.remove(f)
os.remove(logdatei)
os.rmdir(tmp)
print("\nSECURITY-LOG OK ✅")
