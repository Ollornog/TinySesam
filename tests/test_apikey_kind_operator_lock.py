"""API key kinds in audit and log, and the operator's lockout as a public method (`auth.set_disabled`).

The kind of an API key is `automation` or `human` (R6-5); the audit lines and the security log name it so, and any
other kind is an input error. `auth.set_disabled(user_id, disabled)` (tier A) has the same effect as the lockout in
the panel, which calls the method.

Until the schema baseline (T-111) this suite also proved the migration of the German values of 0.21.x (schema 12);
that migration is gone with 0.30.0, the checks on a fresh database stayed.

All checks work without extras.
"""
from __future__ import annotations

import ast
import io
import logging
import os
import sys
import tempfile
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI                            # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

from tinysesam import TinySesam, TinySesamConfig               # noqa: E402
from tinysesam.errors import ConfigError, StateError           # noqa: E402
from tinysesam.store import Store                              # noqa: E402
from _kit.report import Report                                 # noqa: E402

r = Report("API key kinds and auth.set_disabled")

PW = "Probe-Pw-12345"
BASE = "https://app.example.com"


def _setup(path: str, post: list | None = None) -> TinySesam:
    a = TinySesam(TinySesamConfig(db_path=path, cookie_secure=False, csrf_enabled=False,
                                  passkey_enabled=False, magiclink_enabled=True,
                                  signup_verify_email=True, base_url=BASE))
    if post is not None:
        a.set_mailer(lambda to, subject, text, html=None: post.append(text))
    return a


def _app(a: TinySesam) -> FastAPI:
    app = FastAPI()
    app.include_router(a.router())

    @app.get("/wer")
    def person(u=Depends(a.require_user)):
        return {"user": u["username"], "via": u.get("_via"), "kind": u.get("_key_kind")}
    return app


# ── (a) Audit and log lines name the kind ──────────────────────────────────────────────────────
# Operators' filters hang on them: the kind of a key appears there as `kind=automation`/`kind=human`, the security
# log line names `'human'`.
# (Mutation probe: `_key_art_audit` returns the English name → (a) red.)
path_g = os.path.join(tempfile.mkdtemp(), "g.db")
g = _setup(path_g)
anna_g = g.create_user("anna", password=PW)
human_g = g.create_api_key(anna_g, name="cli", kind="human")
automaton_g = g.create_api_key(anna_g, name="ci")
_sec = io.StringIO()
_sec_check = logging.StreamHandler(_sec)
from tinysesam.security import seclog  # noqa: E402
seclog.addHandler(_sec_check)
try:
    _cg = TestClient(_app(g))
    _cg.get("/wer", headers={"X-API-Key": automaton_g["key"]})
    _cg.get("/wer", headers={"X-API-Key": human_g["key"]})
finally:
    seclog.removeHandler(_sec_check)
_details = {f"{z['event']}:{m.group(1)}"
            for z in g.store._all("SELECT event, detail FROM audit WHERE event IN ('apikey_create', 'apikey_use')")
            for m in [re.search(r"(?:^| )kind=(\S+)", z["detail"] or "")] if m}
r.check("(a) audit: `apikey_create`/`apikey_use` name the kind with `kind=automation|human` (not `art=`)",
        {"apikey_create:human", "apikey_create:automation", "apikey_use:automation"} <= _details
        and not any(re.search(r"(?:^| )art=", z["detail"] or "") for z in g.store._all(
            "SELECT detail FROM audit WHERE event IN ('apikey_create', 'apikey_use')")), str(_details))
r.check("(a) security log: the human key without a session is named `'human'` in the (English) log text",
        "API key of kind 'human' presented without a matching session" in _sec.getvalue(), _sec.getvalue()[-300:])
g.close()

# ── (b) Any other kind is an input error that names the two kinds ───────────────────────────────
path_e = os.path.join(tempfile.mkdtemp(), "e.db")
e = _setup(path_e)
bert = e.create_user("bert", password=PW)
_texts = {}
for old_name in ("robot", "person"):
    try:
        e.create_api_key(bert, name="x", kind=old_name)
        _texts[old_name] = "accepted"
    except ConfigError as error:
        _texts[old_name] = str(error)
r.check("(b) `create_api_key(kind='robot'|'person')` → ConfigError that names both kinds",
        all("There is no API key kind" in _texts[old] and "'automation'" in _texts[old] and "'human'" in _texts[old]
            for old in ("robot", "person")), str(_texts))
_ce = TestClient(_app(e))
_ce.post("/auth/login", data={"username": "bert", "password": PW}, follow_redirects=False)
_response = _ce.post("/auth/apikeys", json={"name": "x", "kind": "person"})
_standard = _ce.post("/auth/apikeys", json={"name": "y"})
r.check("(b) … via `POST /auth/apikeys` 400 with the same hint; without `kind` an `automation` key",
        _response.status_code == 400 and "'human'" in _response.json()["detail"]
        and _standard.status_code == 200 and _standard.json()["kind"] == "automation"
        and "dropped_roles" in _standard.json(), f"{_response.text[:200]} {_standard.text[:200]}")
e.close()

# ── (c) auth.set_disabled: the operator's lockout with its full effect ─────────────────────────
# (Mutation probes, each individually: remove the ending of sessions in `set_disabled` → red; the
# revocation of the keys → red; `revoke_user_magic_tokens` → red; omit `through_operator=True` → red
# (the confirmation link lifts the lockout); the audit line → red.)
path_f = os.path.join(tempfile.mkdtemp(), "f.db")
f = _setup(path_f)
events_f: list = []
f.on_security_event = lambda event, account, details: events_f.append((event, details))
f.ensure_admin("boss", PW)
manager = f.find_user("boss")["id"]
bert_f = f.create_user("bert", password=PW, email="bert@example.com")
app_f = _app(f)
cb = TestClient(app_f)
cb.post("/auth/login", data={"username": "bert", "password": PW}, follow_redirects=False)
key_f = f.create_api_key(bert_f, name="ci")["key"]
link_f = f.create_magic_token("login", user_id=bert_f, email="bert@example.com")
r.check("precondition: bert is signed in, his key works, his sign-in link is open",
        cb.get("/wer").status_code == 200 and f.verify_api_key(key_f)[0] is not None
        and f.peek_magic(link_f) is not None)
_prior = f.store._one("SELECT MAX(id) AS m FROM audit")["m"]
r.check("(c) `set_disabled(uid, True)` without a request → True", f.set_disabled(bert_f, True) is True)
_line = f.store._one("SELECT event, username, ip, detail FROM audit WHERE id > ? AND event='user_disable'",
                      (_prior,))
r.check("(c) … with operator mark, session ended, key revoked, link discarded",
        f.get_user(bert_f)["disabled"] == Store.LOCKED_OPERATOR and cb.get("/wer").status_code == 401
        and f.verify_api_key(key_f) == (None, None) and f.peek_magic(link_f) is None
        and [k["revoked"] for k in f.list_api_keys(bert_f)] == [1])
r.check("(c) … audit `user_disable` under the affected account, event `api_keys_revoked` with `reason`",
        _line is not None and dict(_line) == {"event": "user_disable", "username": "bert", "ip": None,
                                                "detail": f"uid={bert_f} api_keys_revoked=1"}
        and ("api_keys_revoked", {"count": 1, "reason": "account_disabled"}) in events_f,
        f"{_line and dict(_line)} {events_f}")
_verify = f.create_magic_token("verify_email", user_id=bert_f, email="bert@example.com")
_v = TestClient(app_f).post(f"/auth/verify/{_verify}", follow_redirects=False)
r.check("(c) … a confirmation link that only arises afterwards does not lift the lockout (H-18)",
        _v.status_code == 403 and f.get_user(bert_f)["disabled"] == Store.LOCKED_OPERATOR, str(_v.status_code))
r.check("(c) `set_disabled(uid, False)` unlocks; the revoked key stays revoked, the ended "
        "session stays ended (otherwise it would revive with the unlock)",
        f.set_disabled(bert_f, False) is True and f.get_user(bert_f)["disabled"] == 0
        and f.verify_api_key(key_f) == (None, None) and cb.get("/wer").status_code == 401
        and f.store.list_sessions(bert_f) == []
        and f.store._one("SELECT 1 FROM audit WHERE event='user_enable' AND username='bert' "
                         "AND detail=?", (f"uid={bert_f}",)) is not None)
_prior = f.store._one("SELECT MAX(id) AS m FROM audit")["m"]
try:
    f.set_disabled(manager, True)
    _owner = "gesperrt"
except StateError:
    _owner = "StateError"
r.check("(c) an owner cannot be locked: StateError, and nothing happened",
        _owner == "StateError" and f.get_user(manager)["disabled"] == 0
        and f.store._one("SELECT 1 FROM audit WHERE id > ?", (_prior,)) is None, _owner)
r.check("(c) an unknown account: False, no audit row",
        f.set_disabled(9999, True) is False
        and f.store._one("SELECT 1 FROM audit WHERE id > ?", (_prior,)) is None)

# The panel calls exactly this method — and writes the same line as up to 0.21.x: the admin as
# account, its IP, `uid=… api_keys_revoked=…`.
ca = TestClient(app_f)
ca.post("/auth/login", data={"username": "boss", "password": PW}, follow_redirects=False)
f.create_api_key(bert_f, name="two")
_prior = f.store._one("SELECT MAX(id) AS m FROM audit")["m"]
_p = ca.post(f"/auth/admin/api/users/{bert_f}/disable", json={"disabled": True})
_line = f.store._one("SELECT event, username, ip, detail FROM audit WHERE id > ? AND event='user_disable'",
                      (_prior,))
r.check("(c) panel: 200, same effect, audit under the admin with his IP (as up to 0.21.x)",
        _p.status_code == 200 and f.get_user(bert_f)["disabled"] == Store.LOCKED_OPERATOR
        and _line is not None and dict(_line) == {"event": "user_disable", "username": "boss",
                                                    "ip": "testclient",
                                                    "detail": f"uid={bert_f} api_keys_revoked=1"},
        f"{_p.status_code} {_line and dict(_line)}")
r.check("(c) panel: an unknown account → 404 instead of 200 (up to 0.21.x “ok” and an audit row)",
        ca.post("/auth/admin/api/users/9999/disable", json={"disabled": True}).status_code == 404)
f.close()

# One source: the panel route hands over to `PanelActions.disable` (shared with the approvals, stage A), which calls
# `auth.set_disabled` and none of the steps itself.
_admin = ast.parse((ROOT / "tinysesam" / "admin.py").read_text(encoding="utf-8"))
_route = next(k for k in ast.walk(_admin) if isinstance(k, ast.AsyncFunctionDef) and k.name == "user_disable")
_action = next(k for k in ast.walk(_admin) if isinstance(k, ast.FunctionDef) and k.name == "disable")
_call = {ast.unparse(k.func) for k in ast.walk(_route) if isinstance(k, ast.Call)}
_call_action = {ast.unparse(k.func).replace("self.auth.", "auth.") for k in ast.walk(_action)
                if isinstance(k, ast.Call)}
_everywhere = {ast.unparse(k.func).replace("self.auth.", "auth.") for k in ast.walk(_admin) if isinstance(k, ast.Call)}
r.check("(c) one source: `user_disable` → `PanelActions.disable` calls `auth.set_disabled`, no step itself; "
        "admin.py calls `store.set_disabled` nowhere",
        "pa.disable" in _call and "auth.set_disabled" in _call_action
        and not (_call | _call_action) & {"auth.store.set_disabled", "auth.store.delete_user_sessions",
                                          "auth._keys_revoked", "auth.store.revoke_user_magic_tokens",
                                          "auth.audit"}
        and "auth.store.set_disabled" not in _everywhere, str(sorted(_call | _call_action)))

raise SystemExit(r.done())
