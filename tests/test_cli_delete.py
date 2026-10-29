"""CLI: `tinysesam delete --db <file> <user>` (T-27) — remove an account as operator.

Occasion: an acceptance test with a test account against an OIDC-only instance (no admin panel, no
account page) left a local account behind, and the CLI had no way to remove it. A raw `DELETE` would
leave the name in every audit row.

What is pinned here:
  * the command goes through the ONE deletion path (`Store.konto_entfernen`) — the result is the same as
    deleting through `TinySesam.delete_user` (the panel): rows gone, audit anonymised as `deleted#<id>`;
  * the protection rules are the panel's (owner, last admin), taken from the same function;
  * confirmation: asks on a terminal, `--yes` for scripts, no terminal and no `--yes` -> nothing happens;
  * the output names counts and the name, never a secret.

(Mutation probes, run by hand and listed in the CHANGELOG: `Store.konto_entfernen` replaced by
`Store.delete_user` in `_delete` -> the audit checks turn red; `store.loeschsperre` check removed
from `_delete` -> the owner / last-admin checks turn red; the terminal check removed -> the
"no terminal" check turns red.)
"""
import io
import os
import re
import sys
import tempfile
import contextlib

from tinysesam import TinySesam, TinySesamConfig
from tinysesam.__main__ import main

IDP = "https://idp.example.com"


def ok(name):
    print(f"  ✓ {name}")


class _Terminal(io.StringIO):
    """stdin that claims to be a terminal and answers the question."""

    def isatty(self):
        return True


def cli(*argv, stdin="", tty=False):
    """Call main(), collect output and exit code."""
    alt = sys.stdin
    sys.stdin = _Terminal(stdin) if tty else io.StringIO(stdin)
    aus, code = io.StringIO(), 0
    try:
        with contextlib.redirect_stdout(aus), contextlib.redirect_stderr(aus):
            main(list(argv))
    except SystemExit as e:
        code = e.code or 0
    finally:
        sys.stdin = alt
    return code, aus.getvalue()


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, cookie_secure=False, passkey_enabled=False))
st = auth.store


def oidc_konto(name, sub, mail):
    """An account as the OIDC login creates it: `users` + `oidc_identity`, a session, audit rows."""
    uid = auth.create_user(name, email=mail)
    st.link_oidc(IDP, sub, uid)
    st.create_session(uid, 3600, True, "oidc")
    st.create_session(uid, 3600, False, "oidc")
    auth.audit("login", name, "198.51.100.7", "method=oidc")
    st.audit_log("login_fail", name, "203.0.113.9", "password")
    return uid


def zaehle(uid):
    return {t: st._one(f"SELECT COUNT(*) AS n FROM {t} WHERE user_id=?", (uid,))["n"]
            for t in ("oidc_identity", "session")} | {
        "users": st._one("SELECT COUNT(*) AS n FROM users WHERE id=?", (uid,))["n"]}


def audit_zeilen(name):
    return [dict(z) for z in st._all(
        "SELECT * FROM audit WHERE username=? OR detail LIKE ?", (name, f"%{name}%"))]


boss = auth.create_user("boss", "Geheim-Boss-12345", is_admin=True)
auth.set_owner(boss, True)
zweiter = auth.create_user("zweit", "Geheim-Zweit-12345", is_admin=True)

# ---------- the reference: deleting through the panel's route ----------
ref = oidc_konto("referenz", "sub-ref", "referenz@example.com")
assert zaehle(ref) == {"oidc_identity": 1, "session": 2, "users": 1}
assert auth.delete_user(ref)
ref_audit = [(z["event"], z["username"]) for z in st._all("SELECT * FROM audit ORDER BY id")
             if z["username"] and z["username"].startswith("deleted#")]
assert ref_audit, "reference: the panel route left no anonymised rows"
assert not audit_zeilen("referenz") or all(
    z["username"] != "referenz" for z in audit_zeilen("referenz"))
ok("reference: deleting through TinySesam.delete_user removes the rows and anonymises the audit")

# ---------- the command ----------
uid = oidc_konto("tester", "sub-tester", "tester@example.com")
assert zaehle(uid) == {"oidc_identity": 1, "session": 2, "users": 1}
vorher = len(audit_zeilen("tester"))
assert vorher >= 2

code, aus = cli("delete", "--db", db, "--yes", "tester")
assert code == 0, (code, aus)
assert zaehle(uid) == {"oidc_identity": 0, "session": 0, "users": 0}, zaehle(uid)
ok("delete --yes removes users, oidc_identity and session rows")

ersatz = f"deleted#{uid}"
assert "tester" in aus and "2 session(s)" in aus and "1 identity link(s)" in aus, aus
assert ersatz in aus
assert "tester@example.com" not in aus
ok("the output names the account, the counts and the replacement name — no address")

rest = audit_zeilen("tester")
assert not rest, f"audit rows still carry the name: {rest}"
assert any(z["username"] == ersatz and z["event"] == "login" for z in
           (dict(x) for x in st._all("SELECT * FROM audit"))), "the login row is gone, not anonymised"
assert any(z["username"] == ersatz and z["event"] == "login_fail" for z in
           (dict(x) for x in st._all("SELECT * FROM audit")))
zeile = [dict(z) for z in st._all("SELECT * FROM audit WHERE event='user_delete' AND username=?", (ersatz,))]
assert len(zeile) == 1 and f"uid={uid}" in zeile[0]["detail"] and "source=cli" in zeile[0]["detail"], zeile
ok("audit: rows stay but carry deleted#<id>; one user_delete row (source=cli), as the panel writes it")

# the same shape as the panel's own row
panel_zeile = [dict(z) for z in st._all(
    "SELECT * FROM audit WHERE event='user_delete' AND username=?", (f"deleted#{ref}",))]
assert len(panel_zeile) == 1
assert re.fullmatch(r"uid=\d+ audit_anonymized=\d+", panel_zeile[0]["detail"]), panel_zeile
assert re.fullmatch(r"uid=\d+ audit_anonymized=\d+ source=cli", zeile[0]["detail"]), zeile
ok("the user_delete row has the panel's shape (uid=… audit_anonymized=…) plus the source")

code, aus = cli("delete", "--db", db, "--yes", "tester")
assert code == 1 and "No account 'tester'" in aus, (code, aus)
ok("second call -> exit 1, clear message")

code, aus = cli("delete", "--db", db + ".fehlt", "--yes", "tester")
assert code == 1 and "No database at" in aus and not os.path.exists(db + ".fehlt")
ok("wrong DB path -> clear message, no empty database created")

# ---------- protection rules (the panel's) ----------
code, aus = cli("delete", "--db", db, "--yes", "boss")
assert code == 1 and "owner" in aus and st.get_user(boss) is not None, (code, aus)
ok("an owner is not deleted")

# `zweit` is the last admin when the owner is no admin (inconsistent data, e.g. an owner the
# identity provider demoted): set it up by hand. (With no owner at all the store promotes the oldest
# admin itself at opening, so that state cannot be tested through the command.)
st._exec("UPDATE users SET is_admin=0 WHERE id=?", (boss,))
code, aus = cli("delete", "--db", db, "--yes", "zweit")
assert code == 1 and "last admin" in aus and st.get_user(zweiter) is not None, (code, aus)
try:
    auth.delete_user(zweiter)
    panel_sperrt_admin = False
except Exception:   # noqa: BLE001 — StateError is the expected refusal
    panel_sperrt_admin = True
assert panel_sperrt_admin
ok("the last admin is not deleted (panel route refuses the same account)")
st._exec("UPDATE users SET is_admin=1 WHERE id=?", (boss,))

# the CLI and the panel route refuse in exactly the same cases
for uid_k, name_k in ((boss, "boss"),):
    try:
        auth.delete_user(uid_k)
        panel_sperrt = False
    except Exception:   # noqa: BLE001 — StateError is the expected refusal
        panel_sperrt = True
    assert panel_sperrt and cli("delete", "--db", db, "--yes", name_k)[0] == 1
ok("panel route and CLI refuse the same account")

# ---------- confirmation ----------
u2 = oidc_konto("frage", "sub-frage", "frage@example.com")
code, aus = cli("delete", "--db", db, "frage")
assert code == 1 and "Not a terminal" in aus and st.get_user(u2) is not None, (code, aus)
ok("no --yes and no terminal -> nothing deleted, exit 1")

code, aus = cli("delete", "--db", db, "frage", stdin="n\n", tty=True)
assert code == 1 and "Aborted" in aus and st.get_user(u2) is not None, (code, aus)
assert "2 session(s)" in aus      # the question names what would go
ok("on a terminal the command asks; \"n\" aborts and names what would have been removed")

code, aus = cli("delete", "--db", db, "frage", stdin="", tty=True)
assert code == 1 and st.get_user(u2) is not None, (code, aus)
ok("a closed input counts as \"no\"")

code, aus = cli("delete", "--db", db, "frage", stdin="y\n", tty=True)
assert code == 0 and st.get_user(u2) is None, (code, aus)
ok("\"y\" on a terminal deletes")

# ---------- by ID, for a name that cannot be typed in ----------
u3 = oidc_konto("per-id", "sub-id", "id@example.com")
code, aus = cli("delete", "--db", db, "--yes", f"#{u3}")
assert code == 0 and st.get_user(u3) is None, (code, aus)
ok("#<id> works like in rename")

# ---------- help ----------
code, aus = cli("--help")
assert code == 0 and "delete" in aus
code, aus = cli("delete", "--help")
assert code == 0 and "--yes" in aus and "deleted#<id>" in aus
ok("help names the command")

print("\nCLI delete OK ✅")
