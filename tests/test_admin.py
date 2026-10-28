"""Admin panel: access protection, user/service/key management, blocking/unblocking users,
sessions, hardening, update, audit."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False, oidc_enabled=False, cookie_secure=False))
# This suite checks the blocklist, context words and maximum length — not the single-factor length (B2-4,
# which test_t13_entscheide.py checks). With a minimum length of 15 characters every short weak
# example would already fail on length, and the rule behind it would stay untested.
auth.set_security("password_min_length_single_factor", 8)
auth.ensure_admin("admin", "pw12345")
auth.create_user("bob", password="bobpw", is_admin=False)

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)


def by_name(n):
    return next(u for u in c.get("/auth/admin/api/users").json() if u["username"] == n)


# locked without admin login
assert c.get("/auth/admin/api/users").status_code in (401, 403)
# bob (not an admin) is not allowed
cb = TestClient(app)
cb.post("/auth/login", data={"username": "bob", "password": "bobpw"})
assert cb.get("/auth/admin/api/users").status_code == 403
print("  ✓ Access protection: admins only")

# Admin login
c.post("/auth/login", data={"username": "admin", "password": "pw12345"})
assert c.get("/auth/admin/api/users").status_code == 200
print("  ✓ Admin sees the user list")

# Create service account + key
sid = c.post("/auth/admin/api/users", json={"username": "svc1", "is_service": True, "roles": ["reader"]}).json()["id"]
key = c.post(f"/auth/admin/api/users/{sid}/keys", json={"name": "k1"}).json()["key"]
assert key.startswith("tsk_")
print("  ✓ Admin creates service account + API key")

# BLOCK user (disable, do not delete) → login blocked, account stays
bid = by_name("bob")["id"]
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": True})
assert by_name("bob")["disabled"] is True
assert TestClient(app).post("/auth/login", data={"username": "bob", "password": "bobpw"}).status_code == 401
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": False})
assert by_name("bob")["disabled"] is False
print("  ✓ Admin blocks/unblocks users explicitly (not deleted, login blocked)")

# Self-blocking prevented
mid = by_name("admin")["id"]
assert c.post(f"/auth/admin/api/users/{mid}/disable", json={"disabled": True}).status_code == 400
print("  ✓ Self-blocking prevented")

# Sessions visible + revocable
assert len(c.get("/auth/admin/api/sessions").json()) >= 1
print("  ✓ Sessions can be inspected")

# Read/set hardening
assert "max_login_attempts" in c.get("/auth/admin/api/security").json()
c.post("/auth/admin/api/security", json={"max_login_attempts": 7})
assert auth._sec("max_login_attempts") == 7
print("  ✓ Hardening thresholds can be set in the panel")

# Version — display only. The former update routes are deliberately gone: through them a taken-over
# admin access could have rolled back to an old, vulnerable version.
assert c.get("/auth/admin/api/version").json()["version"][0].isdigit()
for gone in ("/auth/admin/api/update", "/auth/admin/api/update/run"):
    assert c.get(gone).status_code == 404, f"{gone} is still alive"
print("  ✓ Version is displayed; no update endpoint any more")

# Audit + HTML
assert len(c.get("/auth/admin/api/audit").json()) >= 1
assert c.get("/auth/admin").status_code == 200 and "Admin" in c.get("/auth/admin").text
print("  ✓ Audit log + admin UI page")

# R8-3: `rp_name` is text. The login, account and error pages escaped it long ago, the panel put
# it raw into <title> and <h1> — anyone taking the name from a tenant setting or environment
# thereby handed markup to the most powerful page of the installation.
from tinysesam.admin import render_panel  # noqa: E402

auth.cfg.rp_name = "</title><script>alert(1)</script>"
_panel = render_panel(auth, "/auth/admin")
assert "<script>alert(1)" not in _panel and "&lt;/title&gt;&lt;script&gt;" in _panel, \
    "rp_name is raw in the panel"
assert _panel.count("&lt;/title&gt;") == 2, "rp_name not escaped in both places (<title>, <h1>)"
# The mount point goes into a JS string — as a JSON literal, not inserted raw.
_panel_b = render_panel(auth, '/x"</script><script>alert(2)//')
assert "<script>alert(2)" not in _panel_b and 'const B="/x\\"\\u003c/script>' in _panel_b, \
    _panel_b[_panel_b.index("const B="):][:60]
print("  ✓ rp_name and mount point end up escaped in the panel")

# ---------- R6-1: do not strip the last admin ----------
# Without an admin the first-admin path reopens (one-time token in the log), and nobody can undo it
# in the panel. The check happens BEFORE writing: the roles stay unchanged as well.
mid = by_name("admin")["id"]
r = c.post(f"/auth/admin/api/users/{mid}/roles", json={"roles": ["x"], "is_admin": False})
assert r.status_code == 400, r.status_code
assert by_name("admin")["is_admin"] is True and by_name("admin")["roles"] == [], by_name("admin")
# A BLOCKED second admin does not count — it cannot sign in.
bid = by_name("bob")["id"]
assert c.post(f"/auth/admin/api/users/{bid}/roles", json={"roles": [], "is_admin": True}).status_code == 200
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": True})
assert c.post(f"/auth/admin/api/users/{mid}/roles", json={"roles": [], "is_admin": False}).status_code == 400
assert by_name("admin")["is_admin"] is True
# Counter-check: with a second ACTIVE admin, demotion works (the rule does not block everything).
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": False})
assert c.post(f"/auth/admin/api/users/{bid}/roles", json={"roles": [], "is_admin": False}).status_code == 200
assert by_name("bob")["is_admin"] is False and by_name("admin")["is_admin"] is True
print("  ✓ R6-1: last active admin cannot be demoted (blocked ones do not count), otherwise it can")
# (Mutation probe: `and not andere_aktive_admins(uid)` → `and False` in admin.user_roles → red.)

# ---------- R6-2: no admin service account ----------
r = c.post("/auth/admin/api/users", json={"username": "svc2", "is_service": True, "is_admin": True})
assert r.status_code == 400, r.status_code
assert not any(u["username"] == "svc2" for u in c.get("/auth/admin/api/users").json())
assert c.post(f"/auth/admin/api/users/{sid}/roles", json={"roles": ["reader"], "is_admin": True}).status_code == 400
assert by_name("svc1")["is_admin"] is False
print("  ✓ R6-2: a service account becomes admin neither on creation nor via the roles")

# ---------- R6-4 / B2-9: hardening thresholds with limits ----------
from tinysesam import ConfigError, security  # noqa: E402
vorher = auth._sec("max_login_attempts")
for boese in ({"rate_limit_max": 0}, {"max_login_attempts": 0}, {"lockout_window_sec": 10**9},
              {"password_min_length": 1}, {"rate_limit_max": "viele"}, {"gibtsnicht": 5},
              {"max_login_attempts": True}):
    assert c.post("/auth/admin/api/security", json=boese).status_code == 400, boese
# All-or-nothing: a valid value next to an invalid one is NOT written.
assert c.post("/auth/admin/api/security",
              json={"max_login_attempts": vorher + 2, "rate_limit_max": 0}).status_code == 400
assert auth._sec("max_login_attempts") == vorher and auth._sec("rate_limit_max") == 30
try:
    auth.set_security("rate_limit_max", 0)
    raise AssertionError("set_security nahm 0 an")
except ConfigError:
    pass
# A value already in the database (version without limits): it is pulled to the nearest
# limit — 0 would paralyse the instance, the lower bound keeps it alive.
auth.store.set_setting("rate_limit_max", "0")
assert auth._sec("rate_limit_max") == 3, auth._sec("rate_limit_max")
auth.store.set_setting("rate_limit_max", "keine Zahl")          # only the unreadable falls back to the default
assert auth._sec("rate_limit_max") == 30, auth._sec("rate_limit_max")
auth.store.set_setting("rate_limit_max", "30")
print("  ✓ R6-4/B2-9: limits in the panel and in set_security, all-or-nothing, legacy value pulled to the limit")
# (Mutation probe: comment out the range check in security.pruefe_haertung → red.)

# ---------- A1: an upgrade does not loosen a stricter existing setting ----------
# Up to 0.19.x set_security wrote every value. Anyone who had set it STRICTER than the limits of
# the first version allowed silently got the weaker default after the upgrade.
streng = {"max_login_attempts": 2, "pin_max_attempts": 2, "lockout_window_sec": 7 * 86400,
          "rate_limit_window_sec": 7200}
for k, v in streng.items():
    auth.store.set_setting(k, str(v))
    assert auth._sec(k) == v, (k, auth._sec(k))
# Beyond the limit: to the limit, not to the default — the direction of tightening is kept.
auth.store.set_setting("password_min_length", "200")
assert auth._sec("password_min_length") == 128, auth._sec("password_min_length")
auth.store.set_setting("lockout_window_sec", str(10**9))
assert auth._sec("lockout_window_sec") == 30 * 86400, auth._sec("lockout_window_sec")
# What sec() then returns, the panel accepts too — the log line recommends nothing impossible.
assert c.post("/auth/admin/api/security", json={**streng, "password_min_length": 128}).status_code == 200
for k, v in streng.items():
    assert auth._sec(k) == v, (k, auth._sec(k))
auth.set_security("max_login_attempts", 1)                     # one attempt: harsh, but permitted
for k, v in security.SECURITY_DEFAULTS.items():
    auth.set_security(k, v)
auth.set_security("password_min_length_single_factor", 8)      # as above: this is about the rule
print("  ✓ A1: stricter legacy values stay, values beyond the limit end up at the limit")
# (Mutation probe: in manager.sec() `return security.SECURITY_DEFAULTS[key]` again instead of
#  klemme_haertung → red; SECURITY_GRENZEN max_login_attempts (3, …) again → red.)
# Every hardening threshold has limits. Without an entry `pruefe_haertung` raised a KeyError, i.e.
# a 500 in the panel — which happened when three branches each brought a new threshold and none
# updated the limits. The loop above only catches that for the defaults; here it stands as a rule.
assert set(security.SECURITY_GRENZEN) == set(security.SECURITY_DEFAULTS), \
    set(security.SECURITY_GRENZEN) ^ set(security.SECURITY_DEFAULTS)

# ---------- A4: Infinity is a 400, not a 500 ----------
r = c.post("/auth/admin/api/security", content=b'{"max_login_attempts": Infinity}',
           headers={"content-type": "application/json"})
assert r.status_code == 400, r.status_code
try:
    auth.set_security("max_login_attempts", float("inf"))
    raise AssertionError("set_security nahm inf an")
except ConfigError:
    pass
assert auth._sec("max_login_attempts") == security.SECURITY_DEFAULTS["max_login_attempts"]
print("  ✓ A4: Infinity in the panel → 400, in set_security → ConfigError")
# (Mutation probe: remove OverflowError from the except in pruefe_haertung → red.)

# ---------- R6-8: key route answers 400 instead of 500 ----------
for boese in ({"name": "x", "roles": ["gibtsnicht"]}, {"name": "x", "expires_days": 0},
              {"name": "x", "expires_days": "morgen"}):
    r = c.post(f"/auth/admin/api/users/{sid}/keys", json=boese)
    assert r.status_code == 400, (boese, r.status_code)
# Self-service: the same class.
assert c.post("/auth/apikeys", json={"name": "x", "roles": ["gibtsnicht"]}).status_code == 400
print("  ✓ R6-8: unusable scope/expiry → 400 with reason (panel and /auth/apikeys)")

# ---------- R6-6: a key does not mint a key ----------
# (a) fail-closed for a key kind that does not exist: the admin flag is dropped, not only for
#     "automation". Before, `kind="Automat"` (typo in the column) kept the admin rights —
#     a value that the value mapping up to 0.21.x (`automat`/`mensch`) does not know either.
k = auth.create_api_key(mid, name="ci")
auth.store._exec("UPDATE api_key SET kind='Automat' WHERE id=?", (k["id"],))
ohne = TestClient(app)
assert ohne.get("/auth/admin/api/users", headers={"x-api-key": k["key"]}).status_code == 403
# (b) The panel route itself requires a session — independent of whether R6-5 already removes the
#     admin flag. What is simulated is an admin signed in via key (the case R6-5 prevents today);
#     the route must still not issue a key.
echt = auth.current_user
auth.current_user = lambda req: {**dict(auth.store.get_user(mid)), "_via": "apikey"}
try:
    r = ohne.post(f"/auth/admin/api/users/{sid}/keys", json={"name": "gemintet"})
    assert r.status_code == 403, r.status_code
finally:
    auth.current_user = echt
assert not any(x["name"] == "gemintet" for x in auth.list_api_keys(sid))
print("  ✓ R6-6: unknown key kind carries no admin flag; panel key only from a session")
# (Mutation probes: `art != "human"` → `art == "automation"` in current_user → (a) red;
#  remove the `_via` check in admin.user_key_create → (b) red.)

# ---------- B2-13: the panel obeys the same password rule ----------
# Until T-13 the admin path accepted any password — `1` for a new account, `password` when
# resetting. (Mutation probe: delete the two `password_policy_error` calls in admin.py → red.)
r = c.post("/auth/admin/api/users", json={"username": "neu1", "password": "1"})
assert r.status_code == 400 and "zu kurz" in r.json()["detail"], r.text
r = c.post("/auth/admin/api/users", json={"username": "neu1", "password": "password123"})
assert r.status_code == 400 and "leicht zu erraten" in r.json()["detail"], r.text
r = c.post("/auth/admin/api/users", json={"username": "karl", "password": "Karl1990!"})
assert r.status_code == 400, "the username is a context word"
assert auth.store.get_user_by_name("neu1") is None and auth.store.get_user_by_name("karl") is None
r = c.post("/auth/admin/api/users", json={"username": "neu1", "password": "brauchbar-und-lang"})
assert r.status_code == 200, r.text
_bob = auth.store.get_user_by_name("bob")["id"]
r = c.post(f"/auth/admin/api/users/{_bob}/password", json={"password": "Letmein-2024"})
assert r.status_code == 400 and "leicht zu erraten" in r.json()["detail"], r.text
r = c.post(f"/auth/admin/api/users/{_bob}/password", json={"password": "x" * 300})
assert r.status_code == 400 and "zu lang" in r.json()["detail"], r.text
assert auth._check_password("bob", "bobpw"), "rejected means: the old password still applies"
r = c.post(f"/auth/admin/api/users/{_bob}/password", json={"password": "ein-gutes-neues"})
assert r.status_code == 200 and auth._check_password("bob", "ein-gutes-neues")
# Creating without a password stays allowed (SSO/passkey accounts).
assert c.post("/auth/admin/api/users", json={"username": "nurssso"}).status_code == 200
print("  ✓ B2-13: creating and resetting in the panel check length, blocklist and context words")

# ---------- Integration finding 8: roles that are not text → 400 BEFORE any write ----------
# The before/after line (R6-7) was only built AFTER `set_roles`/`set_admin`, with `','.join`.
# With `roles=[1]` that raised: HTTP 500, the admin flag was already in the database, and the
# audit line was missing — an account became admin without it appearing in the log. And as long
# as the roles stayed broken, every further change to the account went through just as unlogged.
# (Mutation probes: delete the `rollen_aus` call in `user_roles` → red (200, `[1]` stored);
#  build the detail line with `sorted(...)` without `str` again → red for the legacy data below.)
import json as _json  # noqa: E402


def _zeilen(ereignis):
    return len([z for z in auth.store.recent_audit(500) if z["event"] == ereignis])


_carl = auth.create_user("carl", password="carl-geheim-1")
_vorher8 = _zeilen("user_roles")
for _koerper in ({"roles": [1], "is_admin": True}, {"roles": [None], "is_admin": True},
                 {"roles": "admin", "is_admin": True}, {"roles": {"a": 1}}, {"roles": ["ok", 2]}):
    r = c.post(f"/auth/admin/api/users/{_carl}/roles", json=_koerper)
    assert r.status_code == 400 and "roles" in r.json()["detail"], (_koerper, r.status_code, r.text)
    _z = auth.store.get_user(_carl)
    assert _json.loads(_z["roles"]) == [] and not _z["is_admin"], (_koerper, dict(_z))
assert _zeilen("user_roles") == _vorher8, "rejected means: nothing written, nothing to log"
# Creating and inviting use the same check — otherwise the broken role would sit in the
# database and hit the next role change.
r = c.post("/auth/admin/api/users", json={"username": "dora", "roles": [1]})
assert r.status_code == 400 and auth.store.get_user_by_name("dora") is None, r.text
r = c.post("/auth/admin/api/users", json={"username": "dora", "roles": ["leser"]})
assert r.status_code == 200 and auth.user_roles(auth.store.get_user_by_name("dora")) == ["leser"], r.text
# Legacy data (from a time without the check): the change goes through AND appears in the log.
auth.store._exec("UPDATE users SET roles=? WHERE id=?", ("[1, null]", _carl))
r = c.post(f"/auth/admin/api/users/{_carl}/roles", json={"roles": ["x"], "is_admin": False})
assert r.status_code == 200, (r.status_code, r.text)
_z8 = [z["detail"] for z in auth.store.recent_audit(20) if z["event"] == "user_roles"]
assert _zeilen("user_roles") == _vorher8 + 1 and "rollen=1,None->x" in _z8[0], _z8
print("  ✓ Finding 8: roles without text → 400 before any write; legacy data is logged instead of 500")

# ---------- Integration finding 10: the panel shows what the server rejects ----------
# Since R6-1/R6-4/B2-13 the server rejects (last admin, hardening value outside the limits,
# weak password) — the panel JS only saw the body: `savesec` reported "saved", `pw`
# "password set", `saveroles` silently reloaded. The admin person believed it had happened.
# (Mutation probes: in `savesec` `await p(…);alert(L.saved)` again → red; remove the look at
#  `r.ok` in `p` → red — with node in the runtime probe, without node in the structure check of
#  `p()` below. Before, the runtime probe silently dropped out without node, and the ci-local image
#  had no node until 2026-09-24: exactly this mutation stayed green there. Final round: in `p`
#  `return {detail:L["err.generic"]}` again → red, with and without node; likewise `(j&&j.detail)||…`.)
import re as _re  # noqa: E402
import subprocess as _sp  # noqa: E402

_panel = c.get("/auth/admin").text
_skripte = [s for s in _re.findall(r"<script\b[^>]*>(.*?)</script\s*>", _panel, _re.S | _re.I)
            if "const ACT={" in s]
assert len(_skripte) == 1, "panel script not found"
_js = _skripte[0]
# Without runtime: every action that calls `p()` routes the result through `abgewiesen` — the next
# new action would otherwise fall into the same hole again.
# What is counted are the actions from ACT (only those are called by a button), without comment lines.
_act = set(_re.search(r"const ACT=\{([^}]*)\}", _js).group(1).split(","))
_stuecke = {m.group(1): "\n".join(z for z in m.group(0).splitlines() if not z.lstrip().startswith("//"))
            for m in _re.finditer(r"(?:async )?function (\w+)\(.*?(?=\n(?:async )?function \w+\(|\nconst ACT=)",
                                  _js, _re.S)}
_schreibend = [n for n in sorted(_act) if _re.search(r"(?<![\w.])p\(", _stuecke.get(n, ""))]
_ohne = [n for n in _schreibend if "abgewiesen(" not in _stuecke[n]]
assert not _ohne, f"Actions without display of the rejection: {_ohne}"
assert len(_schreibend) >= 10 and _act <= set(_stuecke), (_schreibend, _act - set(_stuecke))
# And `p()` itself: without the look at `r.ok` it returns the body on 400/500, and
# `abgewiesen()` sees nothing on a 500 without a JSON body. The runtime probe below needs
# node; this check always runs.
#
# Until the final round it only demanded `if(r.ok)return`, `return {detail:` and the text
# L["err.generic"] somewhere. `return {detail:L["err.generic"]}` passed that: instead of "This is
# the last active admin" the panel only showed "Error", and without node (ci-local) it stayed green (final
# finding audit-3). Now the expression behind `detail:` is read instead of searching by characters: a
# small parser for the part of JavaScript that occurs there (`&&`, `||`, `?:`, `typeof`,
# comparisons, `.`/`?.`/`[…]`) determines which values CAN come out as `detail`, and under
# which conditions. Required: one possible value is the server's reason (`<body>.detail`),
# and only if it is text (`typeof … === "string"`; FastAPI sends a list on 422)
# and the body is not null (checked before or `?.`) — and another one is the fallback text.
# Equivalent as written: `a&&b||c`, `c?a:b`, `j?.detail`, `j["detail"]`, `"string"===typeof …`.
# Limit: this stays structure, not execution. What lies outside that part (a function,
# a template string) is rejected instead of guessed (fail-closed); statements BETWEEN reading the
# body and the return (`j.detail = …`) are not seen by the parser, nor is a
# wrong text key. Only the node runtime probe below covers that.
_JS_TOKEN = _re.compile(r"""\s*(?:(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(?P<op>===|!==|==|!=|&&|\|\||\?\.|[()\[\].?:!])"""
                        r"""|(?P<name>[A-Za-z_$][\w$]*)|(?P<num>\d+(?:\.\d+)?))""")


def _js_ausdruck(text):
    """Read a JS expression from the small part above — as nested tuples."""
    toks, i = [], 0
    while i < len(text):
        if text[i:].strip() == "":
            break
        m = _JS_TOKEN.match(text, i)
        if not m or m.end() == i:
            raise ValueError(f"nicht auswertbar ab {text[i:i + 20]!r}")
        art = m.lastgroup
        toks.append((art, m.group(art)))
        i = m.end()
    pos = [0]

    def nimm(wert=None):
        if pos[0] < len(toks) and (wert is None or toks[pos[0]][1] == wert):
            pos[0] += 1
            return toks[pos[0] - 1]
        return None

    def muss(wert):
        if not nimm(wert):
            raise ValueError(f"erwartet {wert!r} bei Stück {pos[0]}")

    def bedingt():
        a = oder()
        if nimm("?"):
            x = bedingt()
            muss(":")
            return ("cond", a, x, bedingt())
        return a

    def kette(art, op, weiter):
        teile = [weiter()]
        while nimm(op):
            teile.append(weiter())
        return teile[0] if len(teile) == 1 else (art, teile)

    def oder():
        return kette("or", "||", und)

    def und():
        return kette("and", "&&", gleich)

    def gleich():
        a = einstellig()
        while pos[0] < len(toks) and toks[pos[0]][1] in ("===", "!==", "==", "!="):
            op = nimm()[1]
            a = ("eq", op, a, einstellig())
        return a

    def einstellig():
        if nimm("!"):
            return ("not", einstellig())
        if nimm("typeof"):
            return ("typeof", einstellig())
        return glied()

    def glied():
        t = nimm()
        if t is None:
            raise ValueError("Ausdruck endet zu früh")
        if t[1] == "(":
            a = bedingt()
            muss(")")
        elif t[0] in ("name", "num"):
            a = (t[0], t[1])
        elif t[0] == "str":
            a = ("str", t[1][1:-1])
        else:
            raise ValueError(f"unerwartet {t[1]!r}")
        while True:
            if nimm(".") or nimm("?."):
                optional = toks[pos[0] - 1][1] == "?."
                n = nimm()
                if not n or n[0] != "name":
                    raise ValueError("nach . fehlt ein Name")
                a = ("mem", a, n[1], optional)
            elif nimm("["):
                k = bedingt()
                muss("]")
                if k[0] != "str":
                    raise ValueError("Index ist kein fester Text")
                a = ("mem", a, k[1], False)
            else:
                return a

    baum = bedingt()
    if pos[0] != len(toks):
        raise ValueError(f"Rest nach dem Ausdruck: {toks[pos[0]:][:3]}")
    return baum


def _js_ergebnisse(a, bedingungen=()):
    """Every value the expression can yield as a result (except the short-circuited
    falsy ones), with the conditions that were true then, in this order."""
    if a[0] == "or":
        return [e for t in a[1] for e in _js_ergebnisse(t, bedingungen)]
    if a[0] == "and":
        return _js_ergebnisse(a[1][-1], bedingungen + tuple(a[1][:-1]))
    if a[0] == "cond":
        wahr = tuple(a[1][1]) if a[1][0] == "and" else (a[1],)   # `x&&y?…` means: x, then y
        return _js_ergebnisse(a[2], bedingungen + wahr) + _js_ergebnisse(a[3], bedingungen)
    return [(a, bedingungen)]


def _p_detail_stelle(code):
    """(Start, end) of the expression behind `return {detail:` — or None."""
    m = _re.search(r"return\s*\{\s*detail\s*:", code)
    if not m:
        return None
    tiefe, i, zeichen = 0, m.end(), None
    while i < len(code):
        c = code[i]
        if zeichen:
            if c == "\\":
                i += 1
            elif c == zeichen:
                zeichen = None
        elif c in "\"'`":
            zeichen = c
        elif c in "([{":
            tiefe += 1
        elif c in ")]}":
            if tiefe == 0:
                return m.end(), i
            tiefe -= 1
        elif c == "," and tiefe == 0:
            return m.end(), i
        i += 1
    return None


def _p_pruefen(code):
    """What p() lacks to pass on a rejection together with its reason — empty if nothing."""
    probleme = []
    rm = _re.search(r"\.then\(\s*(?:async\s*)?\(?\s*(\w+)\s*\)?\s*=>", code)
    r_ = rm.group(1) if rm else "r"
    if not _re.search(rf"if\s*\(\s*{r_}\.ok\s*\)\s*\{{?\s*return", code):
        probleme.append("p() liest r.ok nicht")
    jm = _re.search(rf"(\w+)\s*=\s*await\s+{r_}\.json\(\)", code)
    if not jm:
        probleme.append("p() liest den Körper der Antwort nicht")
    stelle = _p_detail_stelle(code)
    if stelle is None:
        return probleme + ["p() gibt eine Abweisung nicht als {detail: …} zurück"]
    try:
        ergebnisse = _js_ergebnisse(_js_ausdruck(code[stelle[0]:stelle[1]]))
    except ValueError as e:
        return probleme + [f"detail-Ausdruck nicht auswertbar ({e}): {code[stelle[0]:stelle[1]]}"]
    j = jm.group(1) if jm else "j"

    def ist_grund(a):
        return a[0] == "mem" and a[1] == ("name", j) and a[2] == "detail"

    def ist_textpruefung(b):
        if b[0] != "eq" or b[1] not in ("===", "=="):
            return None
        for x, y in ((b[2], b[3]), (b[3], b[2])):
            if x[0] == "typeof" and ist_grund(x[1]) and y == ("str", "string"):
                return x[1]
        return None

    def ist_nicht_null(b):
        return b == ("name", j) or (b[0] == "eq" and b[1] in ("!==", "!=") and ("name", j) in (b[2], b[3])
                                    and ({("name", "null"), ("name", "undefined")} & {b[2], b[3]}))

    def geschuetzt(bedingungen):
        for n, b in enumerate(bedingungen):
            gelesen = ist_textpruefung(b)
            if gelesen and (gelesen[3] or any(ist_nicht_null(v) for v in bedingungen[:n])):
                return True
        return False

    if not any(ist_grund(w) and geschuetzt(bed) for w, bed in ergebnisse):
        probleme.append(f"p() reicht den Grund des Servers ({j}.detail, nur als Text, null-sicher) nicht durch")
    if not any(w == ("mem", ("name", "L"), "err.generic", False) for w, _ in ergebnisse):
        probleme.append('p() hat keinen Rückfalltext L["err.generic"]')
    return probleme


_p_def = _re.search(r"^const p=\(u,b\)=>(.*?)^(?:const|function|async function) ", _js, _re.S | _re.M)
assert _p_def, "p() not found"
_p_code = "\n".join(z for z in _p_def.group(1).splitlines() if not z.lstrip().startswith("//"))
assert not _p_pruefen(_p_code), f"{_p_pruefen(_p_code)}: {_p_code}"
# Self-test: every broken version of p() is noticed, every equivalent spelling is not.
# The versions only swap the expression behind `detail:` (the check finds it itself) or
# replace p() entirely — no text anchor in admin.py.
_p_stelle = _p_detail_stelle(_p_code)
assert _p_stelle, _p_code


def _p_mit(detail):
    return _p_code[:_p_stelle[0]] + detail + _p_code[_p_stelle[1]:]


_p_kaputt = {
    "Schlussfund audit-3": _p_mit('L["err.generic"]'),
    "fester Text statt Grund": _p_mit('(j&&typeof j.detail==="string"&&"Fehler")||L["err.generic"]'),
    "Grund ohne Text- und null-Prüfung": _p_mit('j.detail||L["err.generic"]'),
    "Grund ohne Textprüfung": _p_mit('(j&&j.detail)||L["err.generic"]'),
    "typeof vor der null-Prüfung": _p_mit('(typeof j.detail==="string"&&j&&j.detail)||L["err.generic"]'),
    "Textprüfung verneint": _p_mit('(j&&typeof j.detail!=="string"&&j.detail)||L["err.generic"]'),
    "Textprüfung an einem anderen Feld": _p_mit('(j&&typeof j.fehler==="string"&&j.detail)||L["err.generic"]'),
    "null-Prüfung verneint": _p_mit('(!j&&typeof j.detail==="string"&&j.detail)||L["err.generic"]'),
    "Grund aus einer anderen Variable": _p_mit('(j&&typeof j.detail==="string"&&k.detail)||L["err.generic"]'),
    "Zweige vertauscht": _p_mit('j&&typeof j.detail==="string"?L["err.generic"]:j.detail'),
    "ohne Rückfalltext": _p_mit('(j&&typeof j.detail==="string"&&j.detail)'),
    "Funktionsaufruf (ausserhalb des Teils)": _p_mit('grund(j)||L["err.generic"]'),
    "ohne Blick auf r.ok": _re.sub(r"if\s*\(\s*r\.ok\s*\)\s*return[^;]*;", "", _p_code),
    "Fund 4": '.then(r=>r.json());\n',
    "Fund 7 (Körper immer)": '.then(async r=>{let j=null;try{j=await r.json()}catch(e){} return j});\n',
}
_p_durch = [n for n, c in _p_kaputt.items() if not _p_pruefen(c)]
assert not _p_durch and _p_kaputt["ohne Blick auf r.ok"] != _p_code, f"structure check misses: {_p_durch}"
_p_gleichwertig = [
    'j&&typeof j.detail==="string"?j.detail:L["err.generic"]',
    '(typeof j?.detail==="string"&&j.detail)||L["err.generic"]',
    '(j!==null&&"string"===typeof j["detail"]&&j["detail"])||L[\'err.generic\']',
]
_p_fehlalarm = [d for d in _p_gleichwertig if _p_pruefen(_p_mit(d))]
assert not _p_fehlalarm, f"structure check rejects equivalents: {_p_fehlalarm}"

from voraussetzung import pflicht_werkzeug  # noqa: E402

# If node is missing, that is red — everywhere, not only on GitHub (see `pflicht_werkzeug`). Since the
# ci-local image ships node, level 1 checks exactly as much here as the gate.
# (Mutation probe: with PATH without node → red; with TINYSESAM_OHNE_NODE=1 → ⚠ line.)
_node = pflicht_werkzeug("node", "Fund 10: Laufzeitprobe der Panel-Aktionen")
if _node:
    _probe = ("const A=[];let ANTWORT=null;const E={};\n"
              "const document={cookie:'',addEventListener(){},querySelectorAll:()=>[],"
              "getElementById:i=>E[i]||(E[i]={value:'0',checked:false,textContent:'',innerHTML:''})};\n"
              "const alert=m=>A.push(String(m));const confirm=()=>true;const prompt=()=>'neu-und-lang';\n"
              # The panel reads input fields by their ID as global names (browser behaviour).
              "const kn={value:'k'},ke={value:''};\n"
              "const fetch=async()=>({ok:ANTWORT[0]<400,status:ANTWORT[0],"
              "json:async()=>{if(ANTWORT[1]===null)throw new Error('kein JSON');return ANTWORT[1]}});\n"
              + _js.replace("tabs();users();", "")
              + "\nusers=async()=>{};keys=async()=>{};pks=async()=>{};sessions=async()=>{};\n"
              "const FAELLE=[['savesec',[['rate_limit_max']]],['saveroles',[1]],['pw',[1]],['dis',[1,true]],"
              "['delpk',[1,2,'x']],['revk',[1,1,'x']],['mkkey',[1]],['deluser',[1]]];\n"
              "(async()=>{const E2={};for(const [name,args] of FAELLE){\n"
              "  for(const [k,antw] of [['400',[400,{detail:'Grund vom Server'}]],['500',[500,null]],"
              "['200',[200,{ok:true}]]]){\n"
              "    ANTWORT=antw;A.length=0;await (globalThis[name]||eval(name))(...args);"
              "E2[name+' '+k]=[...A]}}\n"
              "  process.stdout.write(JSON.stringify(E2))})();\n")
    _aus = _sp.run([_node, "-e", _probe], capture_output=True, text=True, timeout=30)
    assert _aus.returncode == 0, _aus.stderr[-600:]
    _erg = _json.loads(_aus.stdout)
    _Lp = _json.loads(_re.search(r"const L=(\{.*?\});", _js).group(1))   # the texts of the panel
    for _name in ("savesec", "saveroles", "pw", "dis", "delpk", "revk", "mkkey", "deluser"):
        assert _erg[f"{_name} 400"] == ["Grund vom Server"], (_name, _erg[f"{_name} 400"])
        assert len(_erg[f"{_name} 500"]) == 1 and _erg[f"{_name} 500"][0] not in ("", "undefined"), \
            (_name, _erg[f"{_name} 500"])
    assert _erg["savesec 200"] == [_Lp["saved"]] and _erg["pw 200"] == [_Lp["pw_set"]] \
        and _erg["saveroles 200"] == [], _erg
    assert _Lp["saved"] not in _erg["savesec 400"] + _erg["savesec 500"], _erg
    assert _erg["pw 500"] == [_Lp["err.generic"]], _erg
    print("  ✓ Finding 10 (node): 400/500 show the reason instead of \"saved\", 200 stays silent or reports success")
print("  ✓ Finding 10 (structure): every panel action that writes routes the result through abgewiesen(),"
      " and p() reads r.ok and passes on the server's reason")

os.remove(db)
print("\nADMIN-PANEL OK ✅")
