"""CLI: `tinysesam delete --db <file> <user>` (T-27) — remove an account as operator.

Occasion: an acceptance test with a test account against an OIDC-only instance (no admin panel, no
account page) left a local account behind, and the CLI had no way to remove it. A raw `DELETE` would
leave the name in every audit row.

What is pinned here:
  * the command goes through the ONE deletion path (`Store.remove_account`) — the result is the same as
    deleting through `TinySesam.delete_user` (the panel): rows gone, audit anonymised as `deleted#<id>`;
  * the protection rules are the panel's (owner, last admin), taken from the same function;
  * confirmation: asks on a terminal, `--yes` for scripts, no terminal and no `--yes` -> nothing happens;
  * the output names counts and the name, never a secret.

(Mutation probes, run by hand and listed in the CHANGELOG: `Store.remove_account` replaced by
`Store.delete_user` in `_delete` -> the audit checks turn red; `store.deletion_guard` check removed
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
    old = sys.stdin
    sys.stdin = _Terminal(stdin) if tty else io.StringIO(stdin)
    from_, code = io.StringIO(), 0
    try:
        with contextlib.redirect_stdout(from_), contextlib.redirect_stderr(from_):
            main(list(argv))
    except SystemExit as e:
        code = e.code or 0
    finally:
        sys.stdin = old
    return code, from_.getvalue()


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, cookie_secure=False, passkey_enabled=False))
st = auth.store


def oidc_account(name, sub, mail):
    """An account as the OIDC login creates it: `users` + `oidc_identity`, a session, audit rows."""
    uid = auth.create_user(name, email=mail)
    st.link_oidc(IDP, sub, uid)
    st.create_session(uid, 3600, True, "oidc")
    st.create_session(uid, 3600, False, "oidc")
    auth.audit("login", name, "198.51.100.7", "method=oidc")
    st.audit_log("login_fail", name, "203.0.113.9", "password")
    return uid


def count(uid):
    return {t: st._one(f"SELECT COUNT(*) AS n FROM {t} WHERE user_id=?", (uid,))["n"]
            for t in ("oidc_identity", "session")} | {
        "users": st._one("SELECT COUNT(*) AS n FROM users WHERE id=?", (uid,))["n"]}


def audit_lines(name):
    return [dict(z) for z in st._all(
        "SELECT * FROM audit WHERE username=? OR detail LIKE ?", (name, f"%{name}%"))]


boss = auth.create_user("boss", "Secret-Boss-12345", is_admin=True)
auth.set_owner(boss, True)
second = auth.create_user("second", "Secret-Second-12345", is_admin=True)

# ---------- the reference: deleting through the panel's route ----------
ref = oidc_account("reference", "sub-ref", "reference@example.com")
assert count(ref) == {"oidc_identity": 1, "session": 2, "users": 1}
assert auth.delete_user(ref)
ref_audit = [(z["event"], z["username"]) for z in st._all("SELECT * FROM audit ORDER BY id")
             if z["username"] and z["username"].startswith("deleted#")]
assert ref_audit, "reference: the panel route left no anonymised rows"
assert not audit_lines("reference") or all(
    z["username"] != "reference" for z in audit_lines("reference"))
ok("reference: deleting through TinySesam.delete_user removes the rows and anonymises the audit")

# ---------- the command ----------
uid = oidc_account("tester", "sub-tester", "tester@example.com")
assert count(uid) == {"oidc_identity": 1, "session": 2, "users": 1}
before = len(audit_lines("tester"))
assert before >= 2

code, from_ = cli("delete", "--db", db, "--yes", "tester")
assert code == 0, (code, from_)
assert count(uid) == {"oidc_identity": 0, "session": 0, "users": 0}, count(uid)
ok("delete --yes removes users, oidc_identity and session rows")

replacement = f"deleted#{uid}"
assert "tester" in from_ and "2 session(s)" in from_ and "1 identity link(s)" in from_, from_
assert replacement in from_
assert "tester@example.com" not in from_
ok("the output names the account, the counts and the replacement name — no address")

rest = audit_lines("tester")
assert not rest, f"audit rows still carry the name: {rest}"
assert any(z["username"] == replacement and z["event"] == "login" for z in
           (dict(x) for x in st._all("SELECT * FROM audit"))), "the login row is gone, not anonymised"
assert any(z["username"] == replacement and z["event"] == "login_fail" for z in
           (dict(x) for x in st._all("SELECT * FROM audit")))
line = [dict(z) for z in st._all("SELECT * FROM audit WHERE event='user_delete' AND username=?", (replacement,))]
assert len(line) == 1 and f"uid={uid}" in line[0]["detail"] and "source=cli" in line[0]["detail"], line
ok("audit: rows stay but carry deleted#<id>; one user_delete row (source=cli), as the panel writes it")

# the same shape as the panel's own row
panel_line = [dict(z) for z in st._all(
    "SELECT * FROM audit WHERE event='user_delete' AND username=?", (f"deleted#{ref}",))]
assert len(panel_line) == 1
assert re.fullmatch(r"uid=\d+ audit_anonymized=\d+", panel_line[0]["detail"]), panel_line
assert re.fullmatch(r"uid=\d+ audit_anonymized=\d+ source=cli", line[0]["detail"]), line
ok("the user_delete row has the panel's shape (uid=… audit_anonymized=…) plus the source")

code, from_ = cli("delete", "--db", db, "--yes", "tester")
assert code == 1 and "No account 'tester'" in from_, (code, from_)
ok("second call -> exit 1, clear message")

code, from_ = cli("delete", "--db", db + ".missing", "--yes", "tester")
assert code == 1 and "No database at" in from_ and not os.path.exists(db + ".missing")
ok("wrong DB path -> clear message, no empty database created")

# ---------- protection rules (the panel's) ----------
code, from_ = cli("delete", "--db", db, "--yes", "boss")
assert code == 1 and "owner" in from_ and st.get_user(boss) is not None, (code, from_)
ok("an owner is not deleted")

# `second` is the last admin when the owner is no admin (inconsistent data, e.g. an owner the
# identity provider demoted): set it up by hand. (With no owner at all the store promotes the oldest
# admin itself at opening, so that state cannot be tested through the command.)
st._exec("UPDATE users SET is_admin=0 WHERE id=?", (boss,))
code, from_ = cli("delete", "--db", db, "--yes", "second")
assert code == 1 and "last admin" in from_ and st.get_user(second) is not None, (code, from_)
try:
    auth.delete_user(second)
    panel_locks_admin = False
except Exception:   # noqa: BLE001 — StateError is the expected refusal
    panel_locks_admin = True
assert panel_locks_admin
ok("the last admin is not deleted (panel route refuses the same account)")
st._exec("UPDATE users SET is_admin=1 WHERE id=?", (boss,))

# the CLI and the panel route refuse in exactly the same cases
for uid_k, name_k in ((boss, "boss"),):
    try:
        auth.delete_user(uid_k)
        panel_locks = False
    except Exception:   # noqa: BLE001 — StateError is the expected refusal
        panel_locks = True
    assert panel_locks and cli("delete", "--db", db, "--yes", name_k)[0] == 1
ok("panel route and CLI refuse the same account")

# ---------- confirmation ----------
u2 = oidc_account("question", "sub-question", "question@example.com")
code, from_ = cli("delete", "--db", db, "question")
assert code == 1 and "Not a terminal" in from_ and st.get_user(u2) is not None, (code, from_)
ok("no --yes and no terminal -> nothing deleted, exit 1")

code, from_ = cli("delete", "--db", db, "question", stdin="n\n", tty=True)
assert code == 1 and "Aborted" in from_ and st.get_user(u2) is not None, (code, from_)
assert "2 session(s)" in from_      # the question names what would go
ok("on a terminal the command asks; \"n\" aborts and names what would have been removed")

code, from_ = cli("delete", "--db", db, "question", stdin="", tty=True)
assert code == 1 and st.get_user(u2) is not None, (code, from_)
ok("a closed input counts as \"no\"")

code, from_ = cli("delete", "--db", db, "question", stdin="y\n", tty=True)
assert code == 0 and st.get_user(u2) is None, (code, from_)
ok("\"y\" on a terminal deletes")

# ---------- by ID, for a name that cannot be typed in ----------
u3 = oidc_account("per-id", "sub-id", "id@example.com")
code, from_ = cli("delete", "--db", db, "--yes", f"#{u3}")
assert code == 0 and st.get_user(u3) is None, (code, from_)
ok("#<id> works like in rename")

# ---------- help ----------
code, from_ = cli("--help")
assert code == 0 and "delete" in from_
code, from_ = cli("delete", "--help")
assert code == 0 and "--yes" in from_ and "deleted#<id>" in from_
ok("help names the command")

print("\nCLI delete OK ✅")
