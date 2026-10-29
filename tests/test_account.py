"""Phase 7: built-in account page (self-service) + self-service password change + override."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig
from tinysesam.errors import ConfigError


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, pin_enabled=True))
# This suite checks the blocklist, context words and maximum length — not the single-factor length (B2-4,
# that is checked by test_t13_decisions.py). With a minimum length of 15 characters every short weak
# example would already fail on length, and the rule behind it would stay unchecked.
auth.set_security("password_min_length_single_factor", 8)
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)

# not logged in → redirect to the login
r = c.get("/auth/account", follow_redirects=False)
assert r.status_code == 303 and "/auth/login" in r.headers["location"]
ok("Account page requires login")

c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
html = c.get("/auth/account").text
assert "Konto · admin" in html
assert "Passwort" in html and "PIN" in html and "Zwei-Faktor" in html and "API-Keys" in html
assert "Admin-Panel" in html   # admin sees the link
ok("Account page shows sections (password/PIN/2FA/API keys) + admin link")

# Change password: wrong current one → 403
assert c.post("/auth/password", json={"current": "falsch", "new": "neuespasswort"}).status_code == 403
# too short → 400
assert c.post("/auth/password", json={"current": "geheim123", "new": "x"}).status_code == 400
# correct → 200, afterwards the new login works
_pw = c.post("/auth/password", json={"current": "geheim123", "new": "neuespasswort"}).json()
# Since 0.18.0 the response additionally carries `api_keys_active`: API keys deliberately survive
# the user's own password change, and whoever changes the password after a break-in should see
# that a second door is still open. Hence no equality comparison any more.
assert _pw["ok"] is True and _pw["api_keys_active"] == 0, _pw
c.get("/auth/logout")
assert c.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False).status_code == 401
assert c.post("/auth/login", data={"username": "admin", "password": "neuespasswort"}, follow_redirects=False).status_code == 303
ok("Self-service password change (current password required, minimum length)")

# Robustness: broken JSON body → 400 (not 500)
r = c.post("/auth/password", content="{kaputt}", headers={"Content-Type": "application/json"})
assert r.status_code == 400, r.status_code
ok("broken JSON body → 400 (not 500)")

# ---------- Password rule on the account page (B2-5/H-17, R4-07) ----------
# The same rule as at every place that sets a password: known passwords, trivial sequences and words from
# the context (username, service name) fail, even dressed up; too long ones as well.
# (Mutation probe: `return None` at the start of `passwords.passwort_mangel` → red.)
for _schwach in ("password123", "Passwort2026!", "12345678", "qwertzuiop", "aaaaaaaaaa",
                 "Admin2026!", "test!Test1", "45678901"):
    _r = c.post("/auth/password", json={"current": "neuespasswort", "new": _schwach})
    assert _r.status_code == 400 and "leicht zu erraten" in _r.json()["detail"], (_schwach, _r.text)
# `test!Test1` → core `testtest` (blocklist); `Test` is the rp_name of this instance.
_r = c.post("/auth/password", json={"current": "neuespasswort", "new": "Test-2026"})
assert _r.status_code == 400, "the service name (rp_name) is a context word"
_r = c.post("/auth/password", json={"current": "neuespasswort", "new": "x" * 257})
assert _r.status_code == 400 and "zu lang" in _r.json()["detail"], _r.text
_r = c.post("/auth/password", json={"current": "neuespasswort", "new": "k" + "e1" * 127 + "!"})   # 256 characters
assert _r.status_code == 200, "exactly the maximum length is allowed"
_r = c.post("/auth/password", json={"current": "k" + "e1" * 127 + "!", "new": "neuespasswort"})
assert _r.status_code == 200, _r.text
ok("Account page: blocklist, context words and maximum length (256) take effect")

# The operator's own blocklist (`password_blocklist_file`) — supplements the built-in one.
_liste = os.path.join(tempfile.mkdtemp(), "block.txt")
with open(_liste, "w", encoding="utf-8") as _f:
    _f.write("# Kommentar\nFirmenname2026\n")
_ab = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "b.db"), passkey_enabled=False,
                                password_blocklist_file=_liste))
_ab.set_security("password_min_length_single_factor", 8)       # the list is checked, not the length
assert _ab.password_policy_error("firmenname2026") and _ab.password_policy_error("Firmenname!!")
assert _ab.password_policy_error("ein-ganz-eigenes-wort") is None
# Counter-check against over-eagerness: no composition rules (NIST), a digit sequence without a pattern
# and a passphrase pass.
for _gut in ("24681357", "correct horse battery", "9384756102"):
    assert _ab.password_policy_error(_gut) is None, _gut
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "b.db"), passkey_enabled=False,
                              password_blocklist_file=_liste + ".fehlt"))
    raise AssertionError("missing blocklist was silently ignored")
except ConfigError as _e:
    assert "password_blocklist_file" in str(_e)
ok("password_blocklist_file supplements the list; if the file is missing, startup aborts")

# A-3: leak lists like rockyou.txt mix UTF-8 and Latin-1. Strict UTF-8 reading aborted
# startup with a raw UnicodeDecodeError — exactly on the lists the field is meant for.
# (Mutation probe: delete the Latin-1 fallback line in `passwords.blockliste_lesen` → red.)
_misch = os.path.join(tempfile.mkdtemp(), "leak.txt")
with open(_misch, "wb") as _f:
    _f.write(b"password\nsch\xf6n123\n" + "möhrenkuchen\n".encode("utf-8"))   # Latin-1, then UTF-8
_am = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "b.db"), passkey_enabled=False,
                                password_blocklist_file=_misch))
assert _am.password_policy_error("Schön123!") and _am.password_policy_error("Möhrenkuchen99")
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "b.db"), passkey_enabled=False,
                              password_blocklist_file=os.path.dirname(_misch)))
    raise AssertionError("a directory as blocklist was silently ignored")
except ConfigError as _e:
    assert "password_blocklist_file" in str(_e)
ok("A-3: blocklist with Latin-1 and UTF-8 lines loads; unreadable path stays ConfigError")

# A-5: context words also in their parts — the surname alone is the most obvious word of an
# account `max.mustermann`, and comparing the whole name let it through.
# (Mutation probe: return only `{_kern(roh)}` in `passwords._kontextteile` → red.)
for _pw, _name, _mail in (("Mustermann1990!", "maxm", "max.mustermann@example.com"),
                          ("Schmidt1985!", "anna.schmidt", None),
                          ("Mueller2026!", "km", "k.mueller@example.com"),
                          ("Mustermann1990!", "MaxMustermann", None)):
    assert _ab.password_policy_error(_pw, username=_name, email=_mail), (_pw, _name, _mail)
# Counter-check: parts under four letters (`max`, `k`) count for nothing.
assert _ab.password_policy_error("Maximal-Ruhig-7", username="max.mustermann") is None
ok("A-5: name parts from username and e-mail (separators, inner capitals) are context words")

# A-6: The remaining trivial patterns from the leak lists — descending with wrap-around, repeated
# blocks, doubled sequences, keyboard walks.
# (Mutation probe: replace everything after the ±1 check in `passwords._trivial` with `return False` → red.)
for _muster in ("0987654321", "12341234", "asdfasdf", "abcabcabc", "12121212", "11112222",
                "qwerasdf", "Asdf1234", "7890123456", "aabbccdd", "yxcvbnm123"):
    assert _ab.password_policy_error(_muster), _muster
for _gut in ("24681357", "correct horse battery", "9384756102", "Zauberwald-17", "Tischlampe42"):
    assert _ab.password_policy_error(_gut) is None, _gut
ok("A-6: repeated blocks, keyboard and counting sequences count as trivial")

# ---------- on_security_event (B2-2/H-6) ----------
# Every change to a sign-in factor reaches the hook — the owner should learn about it.
# (Mutation probe: delete `self.security_event("password_changed", …)` from `set_password`
# → red; likewise for each event.)
_ereignisse = []
auth.on_security_event = lambda e, konto, d: _ereignisse.append((e, konto["username"], d))
_uid = auth.store.get_user_by_name("admin")["id"]
assert c.post("/auth/password", json={"current": "neuespasswort", "new": "wieder-ein-neues"}).status_code == 200
auth.set_pin(_uid, "24681357")
auth.disable_pin(_uid)
auth.create_api_key(_uid, name="ci")
_namen = [e for e, _, _ in _ereignisse]
assert _namen == ["password_changed", "pin_set", "pin_disabled", "api_key_created"], _ereignisse
assert all(n == "admin" for _, n, _ in _ereignisse)
assert set(_namen) <= set(auth.SECURITY_EVENTS)
ok("on_security_event: password, PIN set/remove and a new API key report in")

# Every promised event has a caller in the package — also those this test does not drive
# (passkey needs the extra). Via AST, not text search: a docstring does not count.
import ast as _ast
import pathlib as _pl
_gerufen = set()
for _datei in (_pl.Path(__file__).resolve().parent.parent / "tinysesam").glob("*.py"):
    for _k in _ast.walk(_ast.parse(_datei.read_text(encoding="utf-8"))):
        if (isinstance(_k, _ast.Call) and isinstance(_k.func, _ast.Attribute)
                and _k.func.attr == "_security_event" and _k.args
                and isinstance(_k.args[0], _ast.Constant)):
            _gerufen.add(_k.args[0].value)
assert _gerufen == set(auth.SECURITY_EVENTS), (sorted(_gerufen), auth.SECURITY_EVENTS)
ok("every event from SECURITY_EVENTS is triggered somewhere (and no other)")

# A-2: The hook was only in the generated API.md — an integrator nowhere learned which
# events come. The operations notes (both languages) now name each one.
_wurzel = _pl.Path(__file__).resolve().parent.parent
for _doku in ("SECURITY.md", "i18n/SECURITY.de.md"):
    _txt = (_wurzel / _doku).read_text(encoding="utf-8")
    _fehlt = [e for e in auth.SECURITY_EVENTS if f"`{e}`" not in _txt]
    assert "on_security_event" in _txt and not _fehlt, (_doku, _fehlt)
ok("A-2: SECURITY.md (en/de) describes on_security_event with all events")

# A broken hook aborts nothing, but is not silent.
import logging as _logging
from tinysesam import security as _sec
_zeilen = []
_h = _logging.Handler()
_h.emit = lambda rec: _zeilen.append(rec.getMessage())
_sec.seclog.addHandler(_h)


def _kaputt(*_a):
    raise RuntimeError("smtp weg")


auth.on_security_event = _kaputt
_r = c.post("/auth/password", json={"current": "wieder-ein-neues", "new": "neuespasswort"})
_sec.seclog.removeHandler(_h)
auth.on_security_event = None
assert _r.status_code == 200, "a failing hook must not break the password change"
assert any("on_security_event failed" in z and "password_changed" in z for z in _zeilen), _zeilen
assert auth._check_password("admin", "neuespasswort")
ok("on_security_event: error in the hook → operation stands, line in the security log")

# ---------- The delete buttons check the response before they report success (R3-3) ----------
# Both buttons of the account page UNCONDITIONALLY reported "✓ entfernt" and reloaded — even on 403
# (expired step-up freshness, missing CSRF token) or 500. The user saw "removed", the
# factor was still there. The CHANGELOG promises this for BOTH buttons; only `deltotp()` was covered,
# and that in the browser test — which runs a demo with `pin_login=False` and therefore does not show
# the PIN section at all. Mutation M32 (`delpin()` reports success unconditionally again) passed
# 46/46 green. What is checked here is the source the browser actually receives:
# cheaper than a second browser run and independent of which section the demo shows.
# Must come BEFORE the template override further down — after it the page no longer delivers any JS.
import re as _re  # noqa: E402

# Make both sections visible: the PIN section depends on `pin_login`, the 2FA section on
# a confirmed secret. This is exactly what the browser coverage missed — the demo runs
# `pin_login=False` and never shows the PIN button.
_uid = auth.store.get_user_by_name("admin")["id"]
auth.cfg.pin_login = True
auth.totp_begin(_uid)
auth.store.confirm_totp(_uid)
_js = c.get("/auth/account").text
auth.cfg.pin_login = False
_ERFOLG = "TXT.removed"   # the success text now comes from the language table (`TXT`), not literal in the JS


def _funktion(quelle, name):
    """The body of `async function <name>(){…}` up to the next function."""
    _m = _re.search(r"async function " + name + r"\(\)\{(.*?)(?=\nasync function |\n</script>)",
                    quelle, _re.S)
    assert _m, f"{name}() is no longer in the account JS — otherwise this guard checks nothing"
    return _m.group(1)


for _knopf in ("delpin", "deltotp"):
    _koerper = _funktion(_js, _knopf)
    assert "r.ok" in _koerper, f"{_knopf}() does not look at the response at all"
    for _zeile in _koerper.splitlines():
        if _ERFOLG in _zeile:
            assert "r.ok?" in _zeile, \
                f"{_knopf}() reports success unconditionally: {_zeile.strip()!r}"
        if "location.reload()" in _zeile:
            assert "if(r.ok)" in _zeile, \
                (f"{_knopf}() reloads unconditionally: {_zeile.strip()!r} — a 403 would then look "
                 "to the user exactly like a success")
# Counter-check: both buttons are on the page — otherwise the guard measures text nobody
# receives, and the success path would be proven nowhere.
assert "data-act=delpin" in _js and "data-act=deltotp" in _js, "no delete button on the page"
assert _ERFOLG in _funktion(_js, "delpin"), "delpin() no longer reports success at all"
ok("Delete buttons (PIN and 2FA) report success only after `r.ok`")

# The JS texts follow `config.lang` (this suite runs with lang="de"): German here, English once switched.
# (JSON is ASCII-escaped, so "✓" appears as \u2713.)
assert '"removed": "\\u2713 entfernt"' in _js and "\\u2713 removed" not in _js, "lang=de: German JS texts expected"
_lang_alt = auth.cfg.lang
auth.cfg.pin_login = True
auth.cfg.lang = "en"
try:
    _js_en = c.get("/auth/account").text
finally:
    auth.cfg.lang = _lang_alt
    auth.cfg.pin_login = False
assert '"removed": "\\u2713 removed"' in _js_en and "\\u2713 entfernt" not in _js_en, "lang=en: English JS texts expected"
assert '"locale": "de-DE"' in _js and '"locale": "en-GB"' in _js_en, "locale follows the language"
ok("Account page JS texts: English with lang=en, German with lang=de")

# Template override of the account page
auth.set_template("account", lambda a, ctx: f"<html>MEIN-KONTO {ctx['user']['username']}</html>")
assert "MEIN-KONTO admin" in c.get("/auth/account").text
ok("Account page replaceable via set_template")

# R8-6: The user sets key and passkey names themselves, and the account page wrote them raw into
# innerHTML. A key named <img src=x onerror=…> ran as code — also in the browser of an admin
# who looks at the page. Every API field that goes into the markup there must pass through esc0.
from tinysesam.templates import _ACCOUNT_JS  # noqa: E402

_felder = _re.findall(r"(\S{0,6})\b([kps])\.(name|prefix|id|method|ip|user_agent)\b", _ACCOUNT_JS)
_roh = [f"{v}{o}.{f}" for v, o, f in _felder if not v.endswith("esc0(")]
assert _felder and not _roh, f"API fields raw in the markup: {_roh}"
assert "replace(/[&<>\"']/g" in _ACCOUNT_JS, "esc0 does not cover all five characters"
ok("Account page: every API field in the markup passes through esc0")

# Run the real list functions against prepared names with node — the effect,
# not just the source text.
import json as _json  # noqa: E402
import subprocess as _sp  # noqa: E402
from voraussetzung import pflicht_werkzeug  # noqa: E402

# If node is missing, that is red, not silently skipped (see `pflicht_werkzeug`).
# (Mutation probe: run with a PATH without node → red; with TINYSESAM_OHNE_NODE=1 → ⚠ line.)
_node = pflicht_werkzeug("node", "account page: list functions against prepared names")
if _node:
    _boese = '<img src=x onerror=alert(1)>"\'&'
    _daten = {"/auth/apikeys": [{"id": 7, "prefix": "ts_ab", "name": _boese, "revoked": 0}],
              "/auth/passkey/list": [{"id": 3, "name": _boese}],
              "/auth/sessions": [{"created_at": 0, "method": _boese, "ip": _boese,
                                  "user_agent": _boese, "current": 0}]}
    # Like `render_page` for an app at the root: the mount prefix (T-15) is then empty.
    from tinysesam.templates import PRAEFIX_PLATZHALTER as _PP  # noqa: E402
    _skript = _ACCOUNT_JS.split("<script>", 1)[1].rsplit("</script>", 1)[0].replace(_PP, "")
    # `__TXT__` is the language table, which `render_page` fills in (T-29): do the same, in the page's language.
    from tinysesam.templates import _account_texts  # noqa: E402
    _skript = _skript.replace("__TXT__", _account_texts(auth))
    _probe = ("const E={};const document={cookie:'',addEventListener(){},"
              "getElementById:i=>E[i]||(E[i]={innerHTML:''})};"
              f"const D={_json.dumps(_daten)};"
              "const fetch=async u=>({json:async()=>D[u]});const location={};\n"
              + _skript +
              "\nsetTimeout(()=>process.stdout.write(JSON.stringify("
              "[E.keylist.innerHTML,E.pklist.innerHTML,E.sesslist.innerHTML])),50);")
    _aus = _sp.run([_node, "-e", _probe], capture_output=True, text=True, timeout=30)
    assert _aus.returncode == 0, _aus.stderr[-400:]
    _listen = _json.loads(_aus.stdout)
    for _l in _listen:
        assert "<img" not in _l and "&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;" in _l, _l
    ok("Account page (node): prepared key/passkey/session values stay text")

os.remove(db)
print("\nACCOUNT OK ✅")
