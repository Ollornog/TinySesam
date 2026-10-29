"""Findings from operation (2026-09-27) — when embedding into an app with PocketID and in the container.

  (a) Group scope: A group rule on the `groups` claim without the `groups` scope silently rejects
      everyone with PocketID — the configuration check warns, but does not request anything.
  (b) Claim token in the container log: Without an admin, the one-time token for /auth/claim-admin went
      to stderr — in a container that is `docker logs`. If stderr is not a console, it now goes to
      `<db_path>.claim` (0600); the log only names the path and tells the truth.
"""
from __future__ import annotations

import contextlib
import io
import logging
import os
import stat
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import config_check  # noqa: E402
from tinysesam.security import seclog  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Funde aus dem Betrieb (Gruppen-Scope, Claim-Token)")


# ── (a) Group scope────────────────────────────────────────────────────────────────────────────
# PocketID (and every provider that ties claims to scopes) sends `groups` only with the scope
# `groups`. The default `oidc_scopes="openid profile email"` does not request it: with
# `oidc_allowed_groups` nobody got in, with `oidc_group_role_map` nobody got a role —
# and startup said nothing.
# (Mutation probe: remove the call `_groups_scope(...)` in `config_check.check_config` → red.)
OIDC = dict(oidc_enabled=True, oidc_issuer="https://id.example.com", oidc_client_id="app",
            oidc_client_secret="geheim", base_url="https://app.example.com")
FEATURE = "the scope 'groups' is not requested"


def _warnings(**fields):
    error, warnings = config_check.check_config(TinySesamConfig(**{**OIDC, **fields}))
    return error, [w for w in warnings if FEATURE in w]


_f, _w = _warnings(oidc_allowed_groups=["mitarbeiter"])
r.check("(a) oidc_allowed_groups + claim 'groups' + default scopes → exactly one warning, no error; "
        "it names oidc_scopes, PocketID and the way out (gateway: TINYSESAM_OIDC_SCOPES)",
        not [x for x in _f if "groups" in x] and len(_w) == 1
        and "oidc_scopes='openid profile email'" in _w[0] and "PocketID" in _w[0]
        and "TINYSESAM_OIDC_SCOPES" in _w[0], str(_w))
_, _w = _warnings(oidc_group_role_map={"redaktion": "editor"})
r.check("(a) … likewise with oidc_group_role_map alone (no role instead of rejection)", len(_w) == 1, str(_w))
_, _w = _warnings(oidc_allowed_groups=["mitarbeiter"], oidc_scopes="openid profile email groups")
r.check("(a) with the scope 'groups' → no warning", not _w, str(_w))
_cfg = TinySesamConfig(**{**OIDC, "oidc_allowed_groups": ["mitarbeiter"]})
r.check("(a) nothing is requested additionally: oidc_scopes stays as set",
        _cfg.oidc_scopes == "openid profile email")
for _name, _fields in (("ohne Gruppenregel", {}),
                       ("anderer Claim (oidc_group_claim='roles')",
                        {"oidc_allowed_groups": ["x"], "oidc_group_claim": "roles"}),
                       ("OIDC aus", {"oidc_allowed_groups": ["x"], "oidc_enabled": False,
                                     "password_enabled": True}),
                       ("Entra ID (Gruppen über optional claims; ein Scope 'groups' bräche die Anmeldung)",
                        {"oidc_allowed_groups": ["x"],
                         "oidc_issuer": "https://login.microsoftonline.com/mandant/v2.0"})):
    _, _w = _warnings(**_fields)
    r.check(f"(a) no warning: {_name}", not _w, str(_w))

# Per application (T-14): own `scopes`, otherwise the global ones; own group rule, otherwise the global one.
_clients = {"app.example.com": {"client_id": "a", "client_secret": "s"},
            "wiki.example.com": {"client_id": "w", "client_secret": "s",
                                 "scopes": "openid profile email groups"}}
_, _w = _warnings(oidc_allowed_groups=["x"], oidc_scopes="openid groups",
                   oidc_clients={**_clients, "neu.example.com": {"client_id": "n", "client_secret": "s",
                                                                   "scopes": "openid email"}},
                   forward_auth_enabled=True, trusted_redirect_hosts=[])
r.check("(a) per application: an own `scopes` entry without 'groups' is named, the others are not",
        len(_w) == 1 and "oidc_clients['neu.example.com']" in _w[0]
        and "app.example.com" not in _w[0] and "oidc_scopes=" not in _w[0], str(_w))
_, _w = _warnings(oidc_clients={"app.example.com": {"client_id": "a", "client_secret": "s",
                                                     "allowed_groups": ["team-a"]}},
                   forward_auth_enabled=True)
r.check("(a) … a group rule only on the entry, scopes inherited without 'groups' → warned (this client only)",
        len(_w) == 1 and "oidc_clients['app.example.com']" in _w[0] and "oidc_scopes=" not in _w[0], str(_w))

# Gateway: without its own variable the advice could not have been followed — the preset always took the
# default scopes.
from tinysesam import gateway  # noqa: E402

_env = {"TINYSESAM_OIDC_ISSUER": "https://id.example.com", "TINYSESAM_OIDC_CLIENT_ID": "gw",
        "TINYSESAM_OIDC_CLIENT_SECRET": "geheim", "TINYSESAM_BASE_URL": "https://auth.example.com",
        "TINYSESAM_ALLOWED_GROUPS": "mitarbeiter", "TINYSESAM_DB": ":memory:"}
_before = {k: os.environ.get(k) for k in [*_env, "TINYSESAM_OIDC_SCOPES"]}
try:
    os.environ.update(_env)
    os.environ.pop("TINYSESAM_OIDC_SCOPES", None)
    _g_default = gateway.config_from_env()
    os.environ["TINYSESAM_OIDC_SCOPES"] = "openid profile email groups"
    _g_with = gateway.config_from_env()
finally:
    for _k, _v in _before.items():
        if _v is None:
            os.environ.pop(_k, None)
        else:
            os.environ[_k] = _v
_w_default = [w for w in config_check.check_config(_g_default)[1] if FEATURE in w]
_w_with = [w for w in config_check.check_config(_g_with)[1] if FEATURE in w]
r.check("(a) gateway: TINYSESAM_ALLOWED_GROUPS without TINYSESAM_OIDC_SCOPES warns; with "
        "TINYSESAM_OIDC_SCOPES='… groups' the scope arrives and the warning goes away",
        _g_default.oidc_scopes == "openid profile email" and len(_w_default) == 1
        and _g_with.oidc_scopes == "openid profile email groups" and not _w_with,
        f"{_g_default.oidc_scopes!r} {_w_default} {_g_with.oidc_scopes!r} {_w_with}")


# ── (b) Claim-Token im Container-Log ─────────────────────────────────────────────────────────────
# Measured in the container (2026-09-27): stderr IS the log. First the token stood there in plain text,
# then the line "Der Wert steht bewusst NICHT im Log" (German output, quoted). The container is simulated by having
# stderr AND the security logger write into the same buffer — that is `docker logs`.
# (Mutation probe: remove the condition `not console` in `_admin_claim_announce`, or drop the
# fallback to the file → the token is in the buffer again → red.)
PW = "Betrieb-Pw-2026"          # 15 characters: the password alone signs in


class _Console(io.StringIO):
    """stderr on a terminal — `isatty()` is true, otherwise a buffer like any other."""

    def isatty(self):
        return True


def _start(stderr, **fields):
    """Build TinySesam without an admin; stderr and the security log end up together in `stderr`."""
    reason = dict(db_path=str(Path(tempfile.mkdtemp()) / "app.db"), cookie_secure=False,
                 csrf_enabled=False, passkey_enabled=False, allow_signup=True,
                 signup_require_email=False)
    reason.update(fields)
    check = logging.StreamHandler(stderr)
    seclog.addHandler(check)
    try:
        with contextlib.redirect_stderr(stderr):
            auth = TinySesam(TinySesamConfig(**reason))
    finally:
        seclog.removeHandler(check)
    return auth


# Console: as before on stderr — a human is reading there. No file.
_k = _Console()
auth_k = _start(_k)
_tok_k = auth_k.admin_claim_token()
_file_k = auth_k.cfg.db_path + ".claim"
r.check("(b) stderr is a console: the token is there, no file next to the database, and "
        "the log line says „on the console“ without the value",
        f"/auth/claim-admin?token={_tok_k}" in _k.getvalue() and not os.path.exists(_file_k)
        and "is on the console (stderr), not in this line" in _k.getvalue()
        and _k.getvalue().count(_tok_k) == 1, _k.getvalue()[-300:])

# No terminal (container, journal, pipe): file with 0600, only the path in the „log".
_c = io.StringIO()
auth_c = _start(_c)
_tok_c = auth_c.admin_claim_token()
_file_c = auth_c.cfg.db_path + ".claim"
_content_c = Path(_file_c).read_text(encoding="utf-8") if os.path.exists(_file_c) else ""
r.check("(b) stderr is not a console: the token is in <db_path>.claim — only there",
        bool(_tok_c) and _content_c == _tok_c + "\n", repr(_content_c))
r.check("(b) … the file has mode 0600",
        os.path.exists(_file_c) and stat.S_IMODE(os.stat(_file_c).st_mode) == 0o600,
        oct(stat.S_IMODE(os.stat(_file_c).st_mode)) if os.path.exists(_file_c) else "fehlt")
r.check("(b) … the value is NOT in the log (stderr + security log), but the path is, and the "
        "text says where the token is",
        _tok_c not in _c.getvalue() and "claim-admin?token=" not in _c.getvalue()
        and f"is in {_file_c} (mode 0600), not in the log" in _c.getvalue()
        and "deliberately NOT" not in _c.getvalue(), _c.getvalue()[-300:])

# The file carries what it should: redeeming makes the user admin and removes the file.
_app_c = FastAPI()
_app_c.include_router(auth_c.router())
_cl = TestClient(_app_c)
_reg = _cl.post("/auth/register", data={"username": "betreiber", "password": PW}, follow_redirects=False)
_one = _cl.get(f"/auth/claim-admin?token={_content_c.strip()}", follow_redirects=False)
r.check("(b) the token from the file makes the first admin, afterwards the file is gone",
        _reg.status_code == 303 and _one.status_code == 303
        and auth_c.store.get_user_by_name("betreiber")["is_admin"] and not os.path.exists(_file_c),
        f"{_reg.status_code} {_one.status_code} {os.path.exists(_file_c)}")

# A leftover from an earlier run (e.g. admin set later via CLI) disappears at startup.
Path(_file_c).write_text("ALT\n", encoding="utf-8")
_start(io.StringIO(), db_path=auth_c.cfg.db_path)
r.check("(b) if an admin exists, startup removes a leftover <db_path>.claim",
        not os.path.exists(_file_c))

# Expiry: The expired token in the file is no longer valid; the next start writes a new one.
_v = io.StringIO()
auth_v = _start(_v)
_file_v = auth_v.cfg.db_path + ".claim"
_old_v = Path(_file_v).read_text(encoding="utf-8").strip()
auth_v.store.set_setting("admin_claim", f"{_old_v}:{int(time.time()) - 1}")
_uid_v = auth_v.create_user("spaet", password=PW)
_expired = auth_v._consume_admin_claim(_old_v, auth_v.store.get_user(_uid_v))
_start(io.StringIO(), db_path=auth_v.cfg.db_path)
_new_v = Path(_file_v).read_text(encoding="utf-8").strip()
r.check("(b) after expiry the file content is invalid, the next start replaces it",
        not _expired and _new_v and _new_v != _old_v
        and _new_v == auth_v.admin_claim_token(), f"{_expired} {_old_v[:6]} {_new_v[:6]}")

# Fallback without a file: `:memory:` — then only stderr remains, and the text honestly says what that means.
_m = io.StringIO()
auth_m = _start(_m, db_path=":memory:")
_tok_m = auth_m.admin_claim_token()
r.check("(b) :memory: without a console: fallback to stderr, and the log line says that the value "
        "is therefore in the service log (instead of “not in the log”)",
        f"claim-admin?token={_tok_m}" in _m.getvalue()
        and "stderr is NOT a console here: the value is therefore in the service's log" in _m.getvalue()
        and "not in the log" not in _m.getvalue(), _m.getvalue()[-400:])

# Fallback when the file cannot be created (a directory is in its place).
_s = io.StringIO()
_db_s = str(Path(tempfile.mkdtemp()) / "app.db")
os.mkdir(_db_s + ".claim")
auth_s = _start(_s, db_path=_db_s)
_tok_s = auth_s.admin_claim_token()
r.check("(b) file cannot be created: fallback to stderr with reason, honestly named",
        f"claim-admin?token={_tok_s}" in _s.getvalue() and "not writable" in _s.getvalue()
        and "service's log" in _s.getvalue(), _s.getvalue()[-400:])

# A file chosen by the operator takes precedence — even on a console — and remains after redeeming.
_own = str(Path(tempfile.mkdtemp()) / "claim.token")
_e = _Console()
auth_e = _start(_e, admin_claim_token_file=_own)
_tok_e = auth_e.admin_claim_token()
_uid_e = auth_e.create_user("chefin", password=PW)
_ok_e = auth_e._consume_admin_claim(_tok_e, auth_e.store.get_user(_uid_e))
r.check("(b) admin_claim_token_file takes precedence (even on a console): value in the file, not on "
        "stderr, no <db_path>.claim; the own file remains after redeeming (content invalid)",
        Path(_own).read_text(encoding="utf-8") == _tok_e + "\n" and _tok_e not in _e.getvalue()
        and not os.path.exists(auth_e.cfg.db_path + ".claim") and _ok_e and os.path.exists(_own)
        and not auth_e._consume_admin_claim(_tok_e, auth_e.store.get_user(_uid_e)),
        _e.getvalue()[-300:])

sys.exit(r.done())
